
rule Trojan_Win32_Copak_BAK_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 03 29 ff 09 f7 88 02 09 ff 42 89 ff 01 fe 09 ff 81 c3 02 00 00 00 89 f7 01 f6 39 cb 7e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Copak_BAK_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 ff 53 21 ff 01 d2 89 d7 8b 34 24 83 c4 04 29 d7 21 d2 41 09 ff 81 ef a8 48 13 b1 42 81 f9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Copak_BAK_MTB_3{
	meta:
		description = "Trojan:Win32/Copak.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 34 32 21 f8 8b 36 bf ?? ?? ?? ?? 48 89 ff 81 e6 ff 00 00 00 89 f8 42 89 c0 01 f8 81 c7 01 00 00 00 81 fa f4 01 00 00 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}