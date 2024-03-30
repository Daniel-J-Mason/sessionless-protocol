package app.planetnine;

import org.junit.jupiter.api.RepeatedTest;

public class SessionlessEndToEndTest {
    @RepeatedTest(100)
    public void fullSessionlessTest() {
        String[] keys = Sessionless.generateKeysAsHex();
        String privateKey = keys[0];
        String publicKey = keys[1];
        
        String message = "Sessionless message";
        
        String[] signature = Sessionless.signMessage(privateKey, message);
        
        boolean isVerified = Sessionless.verify(publicKey, signature, message);
        
        assert(isVerified);
    }
}
