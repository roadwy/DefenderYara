
rule Trojan_Win32_Lokibot_PA_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 03 45 ?? 73 05 e8 ?? ?? ?? ?? 8a 00 88 45 ?? 8a 45 ?? 34 ?? 8b 55 08 03 55 ?? 73 05 e8 ?? ?? ?? ?? 88 02 ff 45 ?? 81 7d ?? ?? ?? 02 00 75 ce ff 65 08 } //20
		$a_02_1 = {50 6a 40 68 ?? ?? 02 00 8b 45 08 50 e8 } //1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*20+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=22
 
}