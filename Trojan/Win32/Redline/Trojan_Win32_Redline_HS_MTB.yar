
rule Trojan_Win32_Redline_HS_MTB{
	meta:
		description = "Trojan:Win32/Redline.HS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c3 83 e0 03 8a 04 10 30 01 43 8b 45 f0 3b df 72 ca } //01 00 
		$a_01_1 = {61 6c 64 65 72 73 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}