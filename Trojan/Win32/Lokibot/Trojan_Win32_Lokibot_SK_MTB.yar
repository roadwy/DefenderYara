
rule Trojan_Win32_Lokibot_SK_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 06 8b 06 90 05 10 01 90 8d 90 90 ?? ?? ?? ?? 8a 12 80 f2 ?? 03 c3 88 10 ff 06 81 3e ?? ?? ?? ?? 75 } //1
		$a_03_1 = {bb 01 00 00 00 90 05 10 01 90 8b cb 03 c8 c6 01 ?? 90 05 10 01 90 43 4a 75 ?? 5b c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}