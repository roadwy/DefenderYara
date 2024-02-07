
rule Trojan_Win32_TrickBot_EN_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 11 03 c2 33 d2 f7 35 90 01 04 89 55 f8 a1 90 01 04 0f af 05 90 01 04 8b 4d ec 2b c8 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 8b 55 f8 03 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 2b d0 2b 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 03 d0 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 03 45 08 8b 75 0c 8a 0c 0e 32 0c 10 90 00 } //01 00 
		$a_01_1 = {77 00 68 00 6f 00 61 00 6d 00 69 00 2e 00 65 00 78 00 65 00 } //00 00  whoami.exe
	condition:
		any of ($a_*)
 
}