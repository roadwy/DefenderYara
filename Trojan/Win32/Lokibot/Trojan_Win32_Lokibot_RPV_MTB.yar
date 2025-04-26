
rule Trojan_Win32_Lokibot_RPV_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 da 88 55 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 8b 55 f4 03 55 f8 8a 45 ff 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}