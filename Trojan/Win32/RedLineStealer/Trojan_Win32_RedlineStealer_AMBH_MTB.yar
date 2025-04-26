
rule Trojan_Win32_RedlineStealer_AMBH_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d8 88 45 db 0f b6 4d db 03 4d dc 88 4d db 0f b6 55 db f7 d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_RedlineStealer_AMBH_MTB_2{
	meta:
		description = "Trojan:Win32/RedlineStealer.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 83 c1 02 8b 45 f8 01 c8 89 45 f8 8b 45 f8 b9 04 00 00 00 99 f7 f9 83 fa 00 0f 95 c0 34 ?? a8 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}