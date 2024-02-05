
rule Trojan_Win32_EmotetCrypt_MU_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 55 e4 8b 45 f8 8b f3 c1 ee 05 03 75 e8 03 fa 03 c3 33 f8 81 3d 90 02 08 c7 05 90 02 08 75 90 00 } //01 00 
		$a_00_1 = {33 f7 81 3d } //01 00 
		$a_02_2 = {8b 7d fc 2b fe 81 3d 90 02 08 89 7d fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}