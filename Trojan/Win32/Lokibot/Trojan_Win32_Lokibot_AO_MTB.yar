
rule Trojan_Win32_Lokibot_AO_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 89 8c 9d ?? ?? ff ff 25 ff 00 00 00 89 84 bd ?? ?? ff ff 90 05 10 01 90 8a 02 88 45 ?? 90 05 10 01 90 8b 84 9d ?? ?? ff ff 03 84 bd ?? ?? ff ff 90 05 10 01 90 25 ff ?? ?? ?? 79 ?? 48 0d 00 ff ff ff 40 90 05 10 01 90 8a 84 85 ?? ?? ff ff 32 45 ?? 8b 4d ?? 88 01 90 05 10 01 90 ff 45 ?? 42 ff 4d ?? 0f 85 ?? ff ff ff } //1
		$a_03_1 = {33 c0 55 68 ?? ?? ?? 00 64 ff 30 64 89 20 33 c0 a3 ?? ?? ?? 00 90 05 10 01 90 6a 00 58 f7 f0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}