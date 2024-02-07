
rule Trojan_Win32_TrickBotCrypt_EZ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 30 f6 d1 8b c6 3b 75 d4 73 90 01 02 8a d0 2a d3 32 d1 30 10 03 c7 3b 45 d4 72 90 01 01 46 ff 4d fc 75 90 00 } //01 00 
		$a_81_1 = {5b 20 47 4f 4f 44 20 5d } //01 00  [ GOOD ]
		$a_81_2 = {5c 32 5c 64 6c 6c 5c 52 65 6c 65 61 73 65 5c 54 65 73 74 30 31 2e 70 64 62 } //01 00  \2\dll\Release\Test01.pdb
		$a_81_3 = {47 65 74 4d 6f 75 73 65 } //01 00  GetMouse
		$a_81_4 = {31 2e 64 6c 6c } //00 00  1.dll
	condition:
		any of ($a_*)
 
}