
rule Trojan_Win32_Amadey_HRX_MTB{
	meta:
		description = "Trojan:Win32/Amadey.HRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 c5 81 3d 90 01 08 8d 1c 37 c7 05 90 01 08 c7 05 90 01 08 89 44 24 90 01 01 75 90 01 01 6a 90 01 01 6a 90 01 01 6a 90 01 01 ff 15 90 01 04 8d 4c 24 90 01 01 51 8d 54 24 90 01 01 52 8d 44 24 90 01 01 50 6a 90 01 01 ff 15 90 01 04 31 5c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 81 c7 90 01 04 ff 4c 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}