
rule Trojan_Win32_Phorpiex_RB_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 e8 90 01 04 99 b9 ff 7f 00 00 f7 f9 90 02 10 81 c2 e8 03 00 00 52 8d 90 02 06 52 68 90 02 10 50 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Phorpiex_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Phorpiex.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 e8 90 01 04 99 b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 8d 90 01 05 52 68 90 01 04 8d 90 01 05 50 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}