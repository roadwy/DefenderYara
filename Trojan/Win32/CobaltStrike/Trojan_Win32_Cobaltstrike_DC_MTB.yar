
rule Trojan_Win32_Cobaltstrike_DC_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 73 70 79 5c 63 6f 62 61 6c 74 73 74 72 69 6b 65 2d 63 6c 69 65 6e 74 } //01 00  \spy\cobaltstrike-client
		$a_81_1 = {67 69 67 61 62 69 67 73 76 63 } //01 00  gigabigsvc
		$a_81_2 = {43 72 65 61 74 65 50 69 70 65 } //01 00  CreatePipe
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_4 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_81_5 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //01 00  SetEndOfFile
		$a_81_6 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //01 00  CryptEncrypt
		$a_81_7 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //00 00  CreateMutexA
	condition:
		any of ($a_*)
 
}