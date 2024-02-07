
rule Trojan_Win64_Emotetcrypt_FK_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 0a 00 "
		
	strings :
		$a_81_0 = {7a 71 64 67 6d 61 6a 74 73 75 6a 62 6d 6b 2e 64 6c 6c } //01 00  zqdgmajtsujbmk.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00  IsProcessorFeaturePresent
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_4 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //01 00  RaiseException
		$a_81_5 = {62 65 64 76 72 66 6f 6d 61 74 62 78 73 75 73 } //01 00  bedvrfomatbxsus
		$a_81_6 = {62 67 72 76 65 6e 67 68 68 6c 63 6e 6d 65 } //01 00  bgrvenghhlcnme
		$a_81_7 = {66 72 75 65 7a 76 65 69 6e 6c 6a 79 69 74 72 7a } //01 00  fruezveinljyitrz
		$a_81_8 = {67 68 78 7a 6c 78 77 6d 74 78 70 66 6d 76 68 } //00 00  ghxzlxwmtxpfmvh
	condition:
		any of ($a_*)
 
}