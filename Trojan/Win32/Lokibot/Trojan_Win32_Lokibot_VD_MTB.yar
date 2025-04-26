
rule Trojan_Win32_Lokibot_VD_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc bf [0-40] 8a 01 34 ?? 8b d3 03 55 ?? 90 13 88 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Lokibot_VD_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 [0-25] 8b 84 9d ?? ?? ?? ?? 03 84 bd [0-40] 8a 84 85 ?? ?? ?? ?? 32 45 ?? 8b 4d ?? 88 01 ff 45 ?? 42 ff 4d } //2
		$a_03_1 = {8b ce c1 e1 ?? 8b fe c1 ef ?? 03 cf 0f be 3a 03 cf 33 f1 42 48 0f 85 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=2
 
}