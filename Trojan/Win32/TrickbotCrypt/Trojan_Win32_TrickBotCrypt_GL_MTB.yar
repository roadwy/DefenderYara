
rule Trojan_Win32_TrickBotCrypt_GL_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 0f 00 00 00 2b 15 90 01 04 0f af 15 90 01 04 03 d3 2b 15 90 01 04 83 c2 02 0f af d0 8b 44 24 1c 03 d5 03 c2 8b 54 24 10 8a 14 0a 02 15 90 01 04 83 c5 01 30 10 90 00 } //01 00 
		$a_81_1 = {4c 55 58 75 52 66 41 6c 58 68 72 43 5e 39 63 77 29 73 6f 3f 6f 47 52 74 4f 39 54 73 49 4f 48 73 43 2b 71 78 56 57 23 4d 74 65 58 34 48 29 61 } //00 00 
	condition:
		any of ($a_*)
 
}