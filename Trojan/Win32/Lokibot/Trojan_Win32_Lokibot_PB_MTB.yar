
rule Trojan_Win32_Lokibot_PB_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc e8 90 01 04 8b 55 fc 0f b6 54 3a ff 33 c2 50 8b 45 f8 e8 90 01 04 8b 55 f8 0f b6 54 1a ff 33 c2 5a 33 d0 8d 45 90 01 01 e8 90 01 04 8b 55 90 01 01 8d 45 90 01 01 e8 90 01 04 43 8b 45 f8 e8 90 01 04 3b d8 7e 05 bb 01 00 00 00 47 4e 75 90 00 } //20
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*20+(#a_01_1  & 1)*1) >=21
 
}