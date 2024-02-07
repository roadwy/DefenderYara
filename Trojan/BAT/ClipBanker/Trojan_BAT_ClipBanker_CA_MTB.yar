
rule Trojan_BAT_ClipBanker_CA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 6a 6f 6e 20 64 6f 65 5c 44 65 73 6b 74 6f 70 5c 52 65 67 69 73 74 72 79 5c 52 65 67 69 73 74 72 79 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 52 65 67 69 73 74 72 79 2e 70 64 62 } //01 00  C:\Users\jon doe\Desktop\Registry\Registry\obj\Release\Registry.pdb
		$a_01_1 = {24 31 64 33 38 36 38 65 32 2d 33 36 31 32 2d 34 61 34 35 2d 62 63 65 34 2d 64 62 66 61 65 38 34 35 61 33 30 39 } //01 00  $1d3868e2-3612-4a45-bce4-dbfae845a309
		$a_01_2 = {4d 79 2e 43 6f 6d 70 75 74 65 72 } //01 00  My.Computer
		$a_01_3 = {52 65 67 69 73 74 72 79 2e 65 78 65 } //01 00  Registry.exe
		$a_01_4 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 } //01 00  Dispose__Instance
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerHiddenAttribute
	condition:
		any of ($a_*)
 
}