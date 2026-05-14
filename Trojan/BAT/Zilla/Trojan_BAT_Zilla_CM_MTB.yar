
rule Trojan_BAT_Zilla_CM_MTB{
	meta:
		description = "Trojan:BAT/Zilla.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 5f 54 61 62 49 6e 64 65 78 00 54 6f 41 72 72 61 79 00 73 65 74 5f 4b 65 79 00 57 72 65 6e 6c 65 79 } //2 敳彴慔䥢摮硥吀䅯牲祡猀瑥䭟祥圀敲汮祥
		$a_01_1 = {63 68 72 69 73 74 7a 48 4d 6f 6b 33 } //2 christzHMok3
		$a_01_2 = {53 61 6c 74 53 69 7a 65 } //2 SaltSize
		$a_01_3 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //2 SymmetricAlgorithm
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
		$a_01_5 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //2 Rfc2898DeriveBytes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}