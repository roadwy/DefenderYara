
rule Trojan_BAT_SpySnake_MN_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 19 2d 05 26 16 0d 2b 03 0c 2b f9 08 12 03 28 90 01 03 0a 06 03 07 28 90 01 03 06 6f 90 01 03 0a 90 00 } //0a 00 
		$a_03_1 = {3a 00 2f 00 2f 00 34 00 35 00 2e 00 31 00 33 00 39 00 2e 00 31 00 30 00 35 00 2e 00 32 00 32 00 38 00 2f 00 90 02 10 2e 00 6a 00 70 00 65 00 67 00 90 00 } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {24 38 66 61 65 34 38 35 64 2d 36 64 62 62 2d 34 65 61 64 2d 39 66 66 63 2d 38 35 33 35 34 34 62 36 30 39 39 34 } //00 00  $8fae485d-6dbb-4ead-9ffc-853544b60994
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MN_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 51 00 00 00 08 00 00 00 30 00 00 00 2b 00 00 00 24 00 00 00 85 00 00 00 16 } //05 00 
		$a_01_1 = {64 38 65 38 61 62 35 30 2d 31 61 30 31 2d 34 65 32 62 2d 38 62 61 36 2d 62 38 64 30 33 65 39 66 65 62 64 62 } //01 00  d8e8ab50-1a01-4e2b-8ba6-b8d03e9febdb
		$a_01_2 = {4a 61 6d 62 6f } //01 00  Jambo
		$a_01_3 = {4b 75 72 73 6f 76 61 79 61 5f 54 61 6e 63 68 69 6b 69 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  Kursovaya_Tanchiki.Properties
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_5 = {46 6f 72 6d 32 5f 4b 65 79 44 6f 77 6e } //00 00  Form2_KeyDown
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MN_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 66 64 67 64 66 61 64 67 64 2e 64 6c 6c 23 } //01 00  #fdgdfadgd.dll#
		$a_01_1 = {43 52 59 50 54 5f 55 53 45 52 5f 50 52 4f 54 45 43 54 45 44 } //01 00  CRYPT_USER_PROTECTED
		$a_01_2 = {4b 65 65 70 45 78 74 72 61 50 45 44 61 74 61 } //01 00  KeepExtraPEData
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_7 = {47 65 74 46 69 6c 65 4c 6f 63 6b } //01 00  GetFileLock
		$a_01_8 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_9 = {44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 44 00 6c 00 6c 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 54 00 79 00 70 00 65 00 } //00 00  DynamicDllInvokeType
	condition:
		any of ($a_*)
 
}