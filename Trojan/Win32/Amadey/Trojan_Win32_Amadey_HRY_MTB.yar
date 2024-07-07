
rule Trojan_Win32_Amadey_HRY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.HRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f7 c1 ee 90 01 01 03 f5 81 3d 90 01 08 75 90 01 01 52 ff 15 90 01 04 6a 90 01 01 6a 90 01 01 6a 90 01 01 ff 15 90 01 04 33 d2 8b 4c 24 90 01 01 33 ce 8d 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 81 44 24 90 01 05 83 6c 24 90 01 02 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}