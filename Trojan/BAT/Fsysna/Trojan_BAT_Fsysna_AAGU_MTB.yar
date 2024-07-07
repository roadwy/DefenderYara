
rule Trojan_BAT_Fsysna_AAGU_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AAGU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 72 a3 03 00 70 28 90 01 01 00 00 06 26 06 72 ad 03 00 70 28 90 01 01 00 00 06 26 06 72 bd 03 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 02 16 02 8e 69 6f 90 01 01 00 00 0a 0b 2b 00 07 2a 90 00 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}