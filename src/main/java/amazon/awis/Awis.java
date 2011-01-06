package amazon.awis;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Encoder;

/**
 * Demonstrate how to properly sign an AlexaWebInfoService request to the
 * Awis operation.
 */
public class Awis {

  private static final String ACTION_NAME = "UrlInfo";

  private static final String RESPONSE_GROUP_NAME = "TrafficData,LinksInCount";

  private static final String AWS_BASE_URL = "http://awis.amazonaws.com?";

  private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

  private static final String DATEFORMAT_AWS = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

  /**
   * Generate a timestamp for use with AWS request signing
   *
   * @param date
   *            current date
   * @return timestamp
   */
  public static String getTimestampFromLocalTime(Date date) {
    SimpleDateFormat format = new SimpleDateFormat(DATEFORMAT_AWS);
    format.setTimeZone(TimeZone.getTimeZone("GMT"));
    return format.format(date);
  }

  /**
   * Computes RFC 2104-compliant HMAC signature.
   *
   * @param data
   *            The data to be signed.
   * @param key
   *            The signing key.
   * @return The base64-encoded RFC 2104-compliant HMAC signature.
   * @throws java.security.SignatureException
   *             when signature generation fails
   */
  public static String generateSignature(String data, String key) throws java.security.SignatureException {
    String result;
    try {
      // get an hmac_sha1 key from the raw key bytes
      SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(),
          HMAC_SHA1_ALGORITHM);

      // get an hmac_sha1 Mac instance and initialize with the signing key
      Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
      mac.init(signingKey);

      // compute the hmac on input data bytes
      byte[] rawHmac = mac.doFinal(data.getBytes());

      // base64-encode the hmac
      // result = Encoding.EncodeBase64(rawHmac);
      result = new BASE64Encoder().encode(rawHmac);

    } catch (Exception e) {
      throw new SignatureException("Failed to generate HMAC : "
          + e.getMessage());
    }
    return result;
  }

  /**
   * Make a request to the specified Url and return the results as a String
   *
   * @param urlBuffer
   * @return the XML document as a String
   * @throws java.net.MalformedURLException
   * @throws IOException
   */
  public static String makeRequest(String requestUrl) throws java.net.MalformedURLException, IOException {
    URL url = new URL(requestUrl);
    URLConnection conn = url.openConnection();
    InputStream in = conn.getInputStream();

    // Read the response

    StringBuffer sb = new StringBuffer();
    int c;
    int lastChar = 0;
    while ((c = in.read()) != -1) {
      if (c == '<' && (lastChar == '>'))
        sb.append('\n');
      sb.append((char) c);
      lastChar = c;
    }
    in.close();
    return sb.toString();
  }

  /**
   *  Constructs the AWIS api request
   *
   */
  public static String makeUrl(String accessKey, String secretKey, String siteUrl) throws Exception{
     // Get current time
    String timestamp = Awis.getTimestampFromLocalTime(Calendar.getInstance().getTime());
    return Awis.makeUrl(accessKey, secretKey, siteUrl, timestamp);
  }

  /**
   * Constructs AWIS api request for default action of UrlInfo and responseGroup of Rank
   *
   */
  public static String makeUrl(String accessKey, String secretKey, String siteUrl, String timestamp) throws Exception{
    return Awis.makeUrl(accessKey, secretKey, siteUrl, timestamp, ACTION_NAME, RESPONSE_GROUP_NAME);
  }

  public static String makeUrl(String accessKey, String secretKey, String siteUrl, String timestamp, String action, String responseGroup) throws Exception{
    String signature = Awis.generateSignature(action + timestamp, secretKey);

    StringBuffer urlBuffer = new StringBuffer(AWS_BASE_URL);
    urlBuffer.append("&Action=");
    urlBuffer.append(action);
    urlBuffer.append("&ResponseGroup=");
    urlBuffer.append(responseGroup);
    urlBuffer.append("&AWSAccessKeyId=");
    urlBuffer.append(accessKey);
    urlBuffer.append("&Signature=");
    urlBuffer.append(URLEncoder.encode(signature, "UTF-8"));
    urlBuffer.append("&Timestamp=");
    urlBuffer.append(URLEncoder.encode(timestamp, "UTF-8"));
    urlBuffer.append("&Url=");
    urlBuffer.append(URLEncoder.encode(siteUrl, "UTF-8"));

    return urlBuffer.toString();
  }
  
  /**
   * Returns an AWIS response for a given siteUrl
   *
   */
  public static String get(String accessKey, String secretKey, String siteUrl) throws Exception{
    String url = makeUrl(accessKey, secretKey, siteUrl);
    String xmlResponse = makeRequest(url);
    return xmlResponse;
  }
}

