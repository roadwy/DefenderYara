
rule Trojan_Win32_Trickbot_STR_dll{
	meta:
		description = "Trojan:Win32/Trickbot.STR!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 45 39 6d 5a 6d 6c 6a 5a 56 77 78 4e 53 34 77 58 45 39 31 64 47 78 76 62 32 74 63 55 48 4a 76 5a 6d 6c 73 5a 58 4e 63 54 } //01 00 
		$a_01_1 = {03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 } //00 00 
	condition:
		any of ($a_*)
 
}