
rule Trojan_BAT_SpySnake_MK_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 06 06 11 06 9a 1f 10 28 90 01 03 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de 90 00 } //01 00 
		$a_01_1 = {41 6e 61 6c 79 7a 65 43 6f 6e 74 72 6f 6c } //01 00  AnalyzeControl
		$a_01_2 = {4e 65 74 54 6f 53 77 69 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  NetToSwing.Properties
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MK_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {57 97 a2 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 b3 00 00 00 52 00 00 00 96 01 } //03 00 
		$a_01_1 = {33 33 64 61 38 34 30 61 2d 37 31 33 33 2d 34 66 35 61 2d 39 37 34 39 2d 63 30 62 35 62 35 39 32 38 38 36 37 } //03 00  33da840a-7133-4f5a-9749-c0b5b5928867
		$a_01_2 = {4d 61 68 6a 6f 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 } //03 00  Mahjong.Properties
		$a_01_3 = {44 65 62 75 67 5f 49 6e 66 6f 72 6d 61 74 69 6f 6e 4b 65 79 } //03 00  Debug_InformationKey
		$a_01_4 = {54 63 70 4c 69 73 74 65 6e 65 72 } //03 00  TcpListener
		$a_01_5 = {53 6f 63 6b 65 74 45 78 63 65 70 74 69 6f 6e } //03 00  SocketException
		$a_01_6 = {4b 00 69 00 6e 00 67 00 5f 00 42 00 6c 00 61 00 63 00 6b 00 } //00 00  King_Black
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MK_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 64 64 70 6d 6b 49 66 6b 6b } //01 00  mddpmkIfkk
		$a_01_1 = {63 00 68 00 72 00 6f 00 6d 00 5c 00 63 00 68 00 72 00 6f 00 6d 00 2e 00 65 00 78 00 65 00 } //01 00  chrom\chrom.exe
		$a_01_2 = {45 4e 43 4c 6f 67 54 61 62 6c 65 } //01 00  ENCLogTable
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_4 = {44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 44 00 6c 00 6c 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 54 00 79 00 70 00 65 00 } //01 00  DynamicDllInvokeType
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_6 = {23 66 64 67 64 66 61 64 67 64 2e 64 6c 6c 23 } //01 00  #fdgdfadgd.dll#
		$a_01_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_9 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_10 = {45 6e 63 72 79 70 74 } //00 00  Encrypt
	condition:
		any of ($a_*)
 
}