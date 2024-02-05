
rule VirTool_Win32_Obfuscator_AZ{
	meta:
		description = "VirTool:Win32/Obfuscator.AZ,SIGNATURE_TYPE_PEHSTR,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a d2 8a 07 90 4f 3c 00 74 f6 47 83 ec 08 68 60 02 00 00 8a d2 6a 40 ff 53 e8 90 89 04 24 8d 05 21 10 40 00 50 8a d2 ff 53 f0 8d 15 09 10 40 00 52 50 ff 53 ec 8a d2 89 44 24 04 33 c0 8a d2 8a 07 90 96 83 c7 fc 8b 07 2b f8 8a d2 8b 2f 90 83 c7 04 8b c7 8b cd 8a d2 c0 4c 08 ff 04 90 80 74 01 ff 98 e2 f1 8a d2 ff 34 24 68 04 01 00 00 ff 53 fc 57 58 03 c5 50 90 ff 74 24 04 ff 53 dc 6a 00 68 80 00 00 00 8a d2 6a 02 6a 00 6a 00 68 00 00 00 40 50 ff 53 f8 40 74 46 8a d2 48 50 56 8a d2 6a 00 8a d2 54 83 2c 24 50 90 55 57 50 ff 53 e4 5e ff 53 f4 } //00 00 
	condition:
		any of ($a_*)
 
}