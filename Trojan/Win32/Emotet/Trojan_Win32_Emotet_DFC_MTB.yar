
rule Trojan_Win32_Emotet_DFC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {03 c1 99 b9 7b 0d 00 00 f7 f9 8b 45 e8 8a 4c 15 00 30 08 } //01 00 
		$a_81_1 = {70 30 49 7a 35 44 72 36 7a 33 52 32 6f 37 53 75 63 54 4f 44 41 6a 78 32 61 6d 6c 32 41 72 6d 6d 47 6e 37 } //00 00 
	condition:
		any of ($a_*)
 
}