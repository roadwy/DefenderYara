
rule Trojan_Win32_NSISInject_GA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 46 69 6c 65 45 78 69 73 74 73 40 34 } //01 00  _FileExists@4
		$a_01_1 = {48 76 44 65 63 6c 59 } //01 00  HvDeclY
		$a_01_2 = {5f 52 65 61 64 46 69 6c 65 43 6f 6e 74 65 6e 74 73 40 31 32 } //01 00  _ReadFileContents@12
		$a_01_3 = {5f 57 72 69 74 65 54 6f 46 69 6c 65 40 31 32 } //01 00  _WriteToFile@12
		$a_01_4 = {4c 6f 61 64 65 72 2e 64 6c 6c } //01 00  Loader.dll
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_6 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //00 00  IsProcessorFeaturePresent
	condition:
		any of ($a_*)
 
}