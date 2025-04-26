
rule VirTool_Win32_Golazagne_A_MTB{
	meta:
		description = "VirTool:Win32/Golazagne.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 72 6f 77 73 65 72 73 2e 64 65 63 6f 64 65 64 4c 6f 67 69 6e 44 61 74 61 } //1 browsers.decodedLoginData
		$a_01_1 = {62 72 6f 77 73 65 72 73 2e 41 73 6e 53 6f 75 72 63 65 44 61 74 61 4d 61 73 74 65 72 50 61 73 73 77 6f 72 64 } //1 browsers.AsnSourceDataMasterPassword
		$a_01_2 = {62 72 6f 77 73 65 72 73 2e 43 68 72 6f 6d 65 45 78 74 72 61 63 74 44 61 74 61 52 75 6e } //1 browsers.ChromeExtractDataRun
		$a_01_3 = {73 79 73 61 64 6d 69 6e 2e 46 69 6c 65 7a 69 6c 6c 61 45 78 74 72 61 63 74 44 61 74 61 52 75 6e } //1 sysadmin.FilezillaExtractDataRun
		$a_01_4 = {73 79 73 61 64 6d 69 6e 2e 72 65 74 72 69 65 76 65 48 6f 73 74 6e 61 6d 65 } //1 sysadmin.retrieveHostname
		$a_01_5 = {67 6f 4c 61 7a 61 67 6e 65 2f 66 69 6c 65 73 79 73 74 65 6d } //1 goLazagne/filesystem
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}