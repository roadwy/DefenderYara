
rule Trojan_BAT_Witch_MA_MTB{
	meta:
		description = "Trojan:BAT/Witch.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 31 63 2d 31 } //01 00  $$method0x600001c-1
		$a_01_1 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 31 66 64 2d 31 } //01 00  $$method0x60001fd-1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_4 = {2e 76 6d 70 30 } //01 00  .vmp0
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_6 = {44 65 62 75 67 } //01 00  Debug
		$a_01_7 = {43 6f 72 72 75 70 74 65 64 } //01 00  Corrupted
		$a_01_8 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //01 00  get_MachineName
		$a_01_9 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_10 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_11 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_12 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_01_13 = {73 65 74 5f 4b 65 79 } //01 00  set_Key
		$a_01_14 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}