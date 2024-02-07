
rule Trojan_Win32_DarkCloud_MBHP_MTB{
	meta:
		description = "Trojan:Win32/DarkCloud.MBHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {d4 38 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 80 35 40 00 40 35 40 00 c0 33 40 00 78 00 00 00 85 00 00 00 8e 00 00 00 8f } //01 00 
		$a_81_1 = {73 76 70 61 41 66 68 57 44 4f 5a 68 63 66 51 74 74 6a 41 55 72 65 4f 70 48 54 47 43 62 48 4d 68 77 57 44 51 75 77 67 65 51 50 46 } //01 00  svpaAfhWDOZhcfQttjAUreOpHTGCbHMhwWDQuwgeQPF
		$a_81_2 = {68 76 6b 4c 78 4b 62 43 74 56 49 68 73 53 78 59 75 42 74 52 70 46 65 6b 5a 72 46 47 6a 4b 5a 74 } //00 00  hvkLxKbCtVIhsSxYuBtRpFekZrFGjKZt
	condition:
		any of ($a_*)
 
}