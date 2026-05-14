
rule Trojan_BAT_XWorm_AC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 13 04 08 0e 04 0e 04 8e 69 12 05 11 07 11 07 8e 69 11 04 11 04 8e 69 12 08 16 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_XWorm_AC_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 07 1f 20 8d 1e 00 00 01 25 d0 5a 00 00 04 28 32 00 00 0a 6f 91 00 00 0a 07 1f 10 8d 1e 00 00 01 25 d0 60 00 00 04 28 32 00 00 0a 6f 92 00 00 0a 06 07 6f 93 00 00 0a 17 73 6c 00 00 0a 25 02 16 02 8e 69 6f 94 00 00 0a 6f 95 00 00 0a 06 28 7a 00 00 06 28 ca 00 00 06 2a } //6
		$a_81_1 = {50 72 6f 63 65 73 73 48 6f 6c 6c 6f 77 69 6e 67 } //2 ProcessHollowing
		$a_81_2 = {76 69 63 74 69 6d 50 72 6f 63 65 73 73 50 61 74 68 } //2 victimProcessPath
	condition:
		((#a_01_0  & 1)*6+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=10
 
}