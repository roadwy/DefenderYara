
rule Trojan_BAT_Jalapeno_AH_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 0c 07 08 16 1a 6f 3f 00 00 0a 26 08 16 28 45 00 00 0a 26 07 16 73 46 00 00 0a } //1
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_00_2 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}