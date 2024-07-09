
rule Trojan_Win32_Qakbotcrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/Qakbotcrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c6 03 45 [0-02] 8b 0d [0-04] 03 4d [0-02] 03 4d [0-02] 03 4d [0-02] 8b 15 [0-04] 8b 35 [0-04] 8a 04 [0-02] 88 04 [0-02] 8b 0d [0-04] 83 c1 01 89 0d [0-04] eb } //1
		$a_02_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 31 0d [0-04] c7 05 [0-04] 00 00 00 00 8b 1d [0-04] 01 1d [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5b 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}