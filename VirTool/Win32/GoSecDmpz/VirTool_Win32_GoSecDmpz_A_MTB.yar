
rule VirTool_Win32_GoSecDmpz_A_MTB{
	meta:
		description = "VirTool:Win32/GoSecDmpz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {64 69 74 72 65 61 64 65 72 2e 44 75 6d 70 65 64 48 61 73 68 2e 48 61 73 68 53 74 72 69 6e 67 } //1 ditreader.DumpedHash.HashString
		$a_01_1 = {64 69 74 72 65 61 64 65 72 2e 53 41 4d 52 52 50 43 53 49 44 2e 52 69 64 } //1 ditreader.SAMRRPCSID.Rid
		$a_01_2 = {64 69 74 72 65 61 64 65 72 2e 4e 65 77 53 41 4d 52 4b 65 72 62 53 74 6f 72 65 64 43 72 65 64 4e 65 77 } //1 ditreader.NewSAMRKerbStoredCredNew
		$a_01_3 = {64 69 74 72 65 61 64 65 72 2e 44 69 74 52 65 61 64 65 72 2e 44 75 6d 70 } //1 ditreader.DitReader.Dump
		$a_01_4 = {73 61 6d 72 65 61 64 65 72 2e 53 41 4d 48 61 73 68 41 45 53 49 6e 66 6f } //1 samreader.SAMHashAESInfo
		$a_01_5 = {73 61 6d 72 65 61 64 65 72 2e 55 73 65 72 5f 41 63 63 6f 75 6e 74 5f 56 } //1 samreader.User_Account_V
		$a_01_6 = {73 61 6d 72 65 61 64 65 72 2e 44 6f 6d 61 69 6e 5f 41 63 63 6f 75 6e 74 5f 46 } //1 samreader.Domain_Account_F
		$a_01_7 = {6e 74 64 73 46 69 6c 65 4c 6f 63 61 74 69 6f 6e } //1 ntdsFileLocation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}