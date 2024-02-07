
rule Trojan_BAT_AgentTesla_BJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0b 06 16 73 90 01 04 73 90 01 04 0c 08 07 6f 90 01 04 dd 90 01 04 08 39 90 01 04 08 6f 90 01 04 dc 07 6f 90 01 04 0d dd 90 00 } //01 00 
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 35 00 2e 00 31 00 31 00 2e 00 31 00 32 00 36 00 2e 00 31 00 38 00 35 00 } //01 00  45.11.126.185
		$a_01_1 = {77 00 77 00 77 00 2e 00 69 00 72 00 69 00 73 00 70 00 61 00 6e 00 65 00 6c 00 2e 00 6f 00 72 00 67 00 2f 00 48 00 61 00 74 00 61 00 4c 00 6f 00 67 00 2e 00 61 00 73 00 68 00 78 00 } //01 00  www.irispanel.org/HataLog.ashx
		$a_01_2 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //01 00  Debugger Detected
		$a_01_3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 44 00 69 00 73 00 6b 00 44 00 72 00 69 00 76 00 65 00 } //01 00  SELECT * FROM Win32_DiskDrive
		$a_01_4 = {70 00 61 00 63 00 6b 00 30 00 2e 00 69 00 72 00 69 00 73 00 70 00 61 00 6e 00 65 00 6c 00 2e 00 6f 00 72 00 67 00 2f 00 70 00 61 00 63 00 6b 00 6c 00 69 00 73 00 74 00 } //01 00  pack0.irispanel.org/packlist
		$a_01_5 = {74 00 65 00 6d 00 70 00 5c 00 50 00 61 00 74 00 63 00 68 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  temp\Patcher.exe
	condition:
		any of ($a_*)
 
}