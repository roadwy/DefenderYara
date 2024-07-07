
rule Trojan_Win32_Qbot_BX_MTB{
	meta:
		description = "Trojan:Win32/Qbot.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 15 f8 15 90 01 02 03 f0 68 90 01 04 ff 15 90 01 04 03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_BX_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f0 68 03 90 01 03 ff 15 90 01 04 8d b4 06 90 01 04 68 90 01 04 ff 15 90 01 04 03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_BX_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d 08 89 01 68 90 01 04 ff 15 90 01 04 8b f0 68 90 01 04 ff 15 90 01 04 8d b4 06 90 01 04 68 90 01 04 ff 15 90 01 04 03 f0 68 90 01 04 ff 15 90 01 04 03 f0 8b 55 90 01 01 8b 02 2b c6 8b 4d 90 01 01 89 01 5e 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}