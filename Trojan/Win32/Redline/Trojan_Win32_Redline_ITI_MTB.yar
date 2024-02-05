
rule Trojan_Win32_Redline_ITI_MTB{
	meta:
		description = "Trojan:Win32/Redline.ITI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 08 83 c5 90 01 01 90 0a 30 00 8b 45 90 01 01 81 6d 90 01 05 81 6d 90 01 05 81 45 90 01 05 81 6d 90 01 05 8b 45 90 01 01 8b 4d 90 00 } //01 00 
		$a_03_1 = {03 c8 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 51 8d 45 90 01 01 50 c7 05 90 01 08 e8 90 01 04 8b 45 90 01 01 33 45 90 01 01 83 25 90 01 05 2b f0 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}