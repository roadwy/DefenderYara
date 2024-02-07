
rule Trojan_Win32_Zenpak_SP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 0d 04 d5 58 00 8a 8c 01 d6 38 00 00 8b 15 7c 7e 58 00 88 0c 02 c9 c2 04 00 } //02 00 
		$a_81_1 = {73 75 67 69 74 6f 7a 65 67 69 74 6f 66 61 2d 70 65 63 65 2e 70 64 62 } //00 00  sugitozegitofa-pece.pdb
	condition:
		any of ($a_*)
 
}