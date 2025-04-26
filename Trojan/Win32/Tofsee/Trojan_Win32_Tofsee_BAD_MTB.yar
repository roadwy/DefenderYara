
rule Trojan_Win32_Tofsee_BAD_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d0 50 5a 6a ?? 8f 03 01 03 83 c3 04 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Tofsee_BAD_MTB_2{
	meta:
		description = "Trojan:Win32/Tofsee.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d7 29 d2 4a 21 fa 89 3b f8 83 db ?? f8 83 d6 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}