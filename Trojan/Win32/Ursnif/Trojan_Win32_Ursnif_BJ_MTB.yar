
rule Trojan_Win32_Ursnif_BJ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BJ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 c9 43 eb 99 f7 e9 8b 4c 24 28 c1 fa 08 8b c2 c1 e8 1f 03 c2 0f af 44 24 44 99 83 c1 3e f7 f9 2b c7 8b 7c 24 0c 8d 94 06 cc fd ff ff 89 54 24 4c } //01 00 
		$a_01_1 = {0f af c6 0f af 44 24 40 89 84 24 c8 00 00 00 b8 87 61 18 86 f7 e1 8b 84 24 c8 00 00 00 2b ca d1 e9 03 ca c1 e9 04 03 c1 29 44 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}