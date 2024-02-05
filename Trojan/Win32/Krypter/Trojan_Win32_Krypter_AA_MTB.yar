
rule Trojan_Win32_Krypter_AA_MTB{
	meta:
		description = "Trojan:Win32/Krypter.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 14 06 e8 90 01 04 30 02 46 59 3b 75 90 01 01 72 90 00 } //01 00 
		$a_03_1 = {55 8b ec 8b 4d 90 01 01 8b 41 90 01 01 69 c0 90 01 04 05 90 01 04 89 41 90 01 01 c1 e8 90 01 01 25 90 01 04 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}