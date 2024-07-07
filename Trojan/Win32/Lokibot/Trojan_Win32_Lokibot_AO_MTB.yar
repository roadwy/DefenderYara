
rule Trojan_Win32_Lokibot_AO_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 89 8c 9d 90 01 02 ff ff 25 ff 00 00 00 89 84 bd 90 01 02 ff ff 90 05 10 01 90 8a 02 88 45 90 01 01 90 05 10 01 90 8b 84 9d 90 01 02 ff ff 03 84 bd 90 01 02 ff ff 90 05 10 01 90 25 ff 90 01 03 79 90 01 01 48 0d 00 ff ff ff 40 90 05 10 01 90 8a 84 85 90 01 02 ff ff 32 45 90 01 01 8b 4d 90 01 01 88 01 90 05 10 01 90 ff 45 90 01 01 42 ff 4d 90 01 01 0f 85 90 01 01 ff ff ff 90 00 } //1
		$a_03_1 = {33 c0 55 68 90 01 03 00 64 ff 30 64 89 20 33 c0 a3 90 01 03 00 90 05 10 01 90 6a 00 58 f7 f0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}