
rule Trojan_Win32_TrickBotCrypt_DZ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {25 25 53 31 7a 30 30 66 6f 4a 36 37 48 5a 7a 71 49 26 50 44 31 54 5a 62 47 2b 79 57 45 51 7a 46 67 62 68 56 66 31 7a 75 41 32 4f 35 23 63 24 2b 6e 65 46 50 33 46 26 38 4e 3f 4e 36 31 4e 46 58 2b 74 37 4d 43 74 4e 37 47 23 37 29 3f 71 76 67 59 3e 77 59 5f 64 76 4b 40 37 } //01 00  %%S1z00foJ67HZzqI&PD1TZbG+yWEQzFgbhVf1zuA2O5#c$+neFP3F&8N?N61NFX+t7MCtN7G#7)?qvgY>wY_dvK@7
		$a_81_1 = {62 6c 61 68 20 62 6c 61 68 20 62 6c 61 68 2e 2e 2e } //01 00  blah blah blah...
		$a_81_2 = {53 74 61 72 74 57 } //00 00  StartW
	condition:
		any of ($a_*)
 
}