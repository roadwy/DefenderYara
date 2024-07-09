
rule Trojan_Win32_Lokibot_XS_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.XS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 90 05 10 01 90 8b c2 03 c3 90 05 10 01 90 c6 00 ?? 90 05 10 01 90 43 81 fb ?? ?? ?? ?? 75 } //1
		$a_03_1 = {55 8b ec 53 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 83 2d ?? ?? ?? ?? 01 0f ?? ?? ?? ?? 00 68 ?? ?? 00 00 68 ?? ?? ?? ?? 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}