
rule Trojan_Win32_Tofsee_EA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f3 33 f7 29 75 f4 83 6d ec 01 0f 85 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Tofsee_EA_MTB_2{
	meta:
		description = "Trojan:Win32/Tofsee.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d e4 8b 55 e4 33 55 ec 89 55 ec 8b 45 ec 29 45 f4 c7 45 cc 00 00 00 00 25 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}