
rule Trojan_Win32_Zbot_GSH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 06 8b 4d a4 81 f1 90 01 04 03 f1 8b 16 c1 c2 90 01 01 83 e2 90 01 01 03 c2 4f 89 03 b9 02 00 00 00 c1 c9 90 01 01 03 d9 85 ff 75 ac e9 3b ff ff ff 8d 49 00 90 00 } //0a 00 
		$a_02_1 = {b9 d9 2d ce 63 81 f1 90 01 04 03 cb 8b 11 03 d3 bf 90 01 04 81 ef 90 01 04 03 fa 8b 37 03 f3 eb 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}