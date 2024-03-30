package app.planetnine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SessionlessKeyGenerationTest {
    @Test
    public void testGenerateKeysAsHex() {
        // Generate the keys
        String[] keys = Sessionless.generateKeysAsHex();
        
        // Verify that keys are generated
        assertNotNull(keys);
        
        assert(keys.length == 2);
    }
    
    @Test
    public void testGenerateKeysAsHexFormat() {
        // When keys are generated
        String[] keys = Sessionless.generateKeysAsHex();
        String privateKey = keys[0];
        String publicKey = keys[1];
        
        // Then each key starts with either '02' or '03' indicating compression prefix
        String prefix = publicKey.substring(0, 2);
        assert(prefix.equals("02") || prefix.equals("03"));
        
        assert(privateKey.length() == 64);
        assert(publicKey.length() == 66);
    }
}
