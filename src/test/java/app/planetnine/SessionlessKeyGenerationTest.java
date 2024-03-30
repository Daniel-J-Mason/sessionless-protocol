package app.planetnine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SessionlessKeyGenerationTest {
    @Test
    public void testGenerateKeysAsHex() {
        String[] keys = Sessionless.generateKeysAsHex();
        
        assertNotNull(keys);
        
        assert(keys.length == 2);
    }
    
    @Test
    public void testGenerateKeysAsHexFormat() {
        String[] keys = Sessionless.generateKeysAsHex();
        String privateKey = keys[0];
        String publicKey = keys[1];
        
        String prefix = publicKey.substring(0, 2);
        assert(prefix.equals("02") || prefix.equals("03"));
        
        assert(privateKey.length() == 64);
        assert(publicKey.length() == 66);
    }
}
