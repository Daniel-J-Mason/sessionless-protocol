package app.planetnine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SessionlessKeyGenerationTest {
    @Test
    public void testGenerateKeysAsHex() {
        String[] keys = Sessionless.generateKeys();
        
        assertNotNull(keys);
        
        assert(keys.length == 2);
    }
    
    @Test
    public void testGenerateKeysAsHexFormat() {
        String[] keys = Sessionless.generateKeys();
        String privateKey = keys[0];
        String publicKey = keys[1];
        
        String prefix = publicKey.substring(0, 2);
        assert(prefix.equals("02") || prefix.equals("03"));
        
        assert(privateKey.length() == 64);
        assert(publicKey.length() == 66);
    }
    
    @Test
    void shouldGenerateSameLengthSignatureForSameInput() {
        // Arrange
        String privateKey = "d7a019f946c78f85ac5553f05324b36e927f47750a49aa46a9fbf488f56c83af"; // Sample private key
        String message = "hello, world";
        
        // Act & Assert
        for(int i = 0; i < 100; i++) {
            String signature = Sessionless.sign(privateKey, message);
            
            // Assert
            assertEquals(128, signature.length(), "Expected signature length of 128");
        }
    }
}
