
rule VirTool_Win32_Obfuscator_TX{
	meta:
		description = "VirTool:Win32/Obfuscator.TX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 c0 64 8b 40 30 56 8b 40 0c 8b 70 1c ad 8b 40 08 5e c3 } //01 00 
		$a_02_1 = {6a 00 81 34 24 90 01 04 ff 75 e0 e8 90 01 04 83 c4 08 50 e8 00 00 00 00 80 2c 24 0e 8b 04 24 8b 40 01 83 c0 05 01 04 24 58 90 00 } //01 00 
		$a_00_2 = {e8 00 00 00 00 5b 32 db 81 e3 00 f0 ff ff 89 5d fc 81 c3 00 0c 00 00 83 eb 04 8b 4d 08 89 0b 8b 45 fc 5b } //01 00 
		$a_00_3 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 } //00 00 
	condition:
		any of ($a_*)
 
}