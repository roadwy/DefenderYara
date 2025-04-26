
rule Trojan_BAT_AgentTesla_MYP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 11 00 00 "
		
	strings :
		$a_80_0 = {35 2e 31 37 32 2e 33 39 2e 32 35 2f 62 72 6f 77 73 65 72 2e 70 68 70 } //5.172.39.25/browser.php  1
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 6f 73 74 6f 6a 61 2e 74 6b 2f 62 72 6f 77 73 65 72 2e 70 68 70 } //https://ostoja.tk/browser.php  1
		$a_80_2 = {54 4f 4a 41 5f 42 72 6f 77 73 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //TOJA_Browser.Properties.Resources  1
		$a_80_3 = {49 6e 76 6f 6b 65 4d 65 74 68 6f 64 2e 49 6e 76 6f 6b 65 4d 65 74 68 6f 64 } //InvokeMethod.InvokeMethod  1
		$a_80_4 = {4d 79 43 6c 61 73 73 } //MyClass  1
		$a_80_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_6 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //MD5CryptoServiceProvider  1
		$a_80_7 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //TripleDESCryptoServiceProvider  1
		$a_80_8 = {73 65 6e 64 65 72 } //sender  1
		$a_80_9 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //get_ResourceManager  1
		$a_80_10 = {43 6f 6d 70 6f 6e 65 6e 74 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //ComponentResourceManager  1
		$a_80_11 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //SymmetricAlgorithm  1
		$a_80_12 = {48 61 73 68 41 6c 67 6f 72 69 74 68 6d } //HashAlgorithm  1
		$a_80_13 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //ICryptoTransform  1
		$a_80_14 = {43 69 70 68 65 72 4d 6f 64 65 } //CipherMode  1
		$a_80_15 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //DebuggerNonUserCodeAttribute  1
		$a_80_16 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //TransformFinalBlock  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1) >=15
 
}