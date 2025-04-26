
rule Trojan_WinNT_Killav_BU{
	meta:
		description = "Trojan:WinNT/Killav.BU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 e4 18 00 00 00 e8 ?? ?? 00 00 85 c0 7c 25 ff 75 08 ff 75 fc e8 ?? ?? 00 00 6a 00 ff 75 fc e8 ?? ?? 00 00 ff 75 fc 8b 35 ?? ?? 01 00 ff d6 ff 75 08 ff d6 } //1
		$a_03_1 = {ab 8b 45 08 89 45 f4 8d 45 f4 50 8d 45 dc 50 68 ff 0f 1f 00 8d 45 fc 50 c7 45 dc 18 00 00 00 ff 15 ?? ?? 01 00 8b 45 fc 5f c9 c2 04 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}