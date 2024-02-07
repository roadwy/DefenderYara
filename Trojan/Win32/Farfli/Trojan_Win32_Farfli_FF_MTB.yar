
rule Trojan_Win32_Farfli_FF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {80 3b 00 8b cb 74 2c 8a 51 01 84 d2 74 25 0f b6 01 0f b6 fa 3b c7 77 14 8b 55 fc 8a 92 58 89 4e 00 08 90 c1 0e 4f 00 40 3b c7 76 f5 41 41 80 39 00 75 d4 } //01 00 
		$a_00_1 = {66 8b 11 f6 c2 01 74 16 80 88 c1 0e 4f 00 10 8a 94 05 ec fd ff ff 88 90 c0 0d 4f 00 eb 1c f6 c2 02 74 10 80 88 c1 0e 4f 00 20 8a 94 05 ec fc ff ff eb e3 80 a0 c0 0d 4f 00 00 40 41 41 3b c6 } //01 00 
		$a_01_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 6a 6d 73 68 6f 6d 65 2e 63 6f 6d 2f 53 65 63 72 65 74 43 68 61 74 2e 68 74 6d } //01 00  http://www.wjmshome.com/SecretChat.htm
		$a_01_4 = {77 77 77 2e 73 77 6f 72 64 61 61 2e 63 6f 6d } //01 00  www.swordaa.com
		$a_01_5 = {6d 61 69 6c 74 6f 3a 77 65 62 6d 61 73 74 65 72 40 77 6a 6d 73 68 6f 6d 65 2e 63 6f 6d 3f } //00 00  mailto:webmaster@wjmshome.com?
	condition:
		any of ($a_*)
 
}