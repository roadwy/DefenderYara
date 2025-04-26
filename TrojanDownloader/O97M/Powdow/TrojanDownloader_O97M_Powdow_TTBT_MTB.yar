
rule TrojanDownloader_O97M_Powdow_TTBT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.TTBT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 28 68 74 6d 6c 56 61 72 69 61 62 6c 65 43 6f 6d 70 73 20 26 20 63 6f 6d 70 73 56 61 72 54 6f 29 } //1 Call VBA.Shell(htmlVariableComps & compsVarTo)
		$a_01_1 = {69 71 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 76 61 72 69 61 62 6c 65 50 72 6f 63 48 74 6d 6c 2e 68 74 61 22 2c 20 22 20 63 2f 20 64 6d 63 22 } //1 iq "c:\users\public\variableProcHtml.hta", " c/ dmc"
		$a_01_2 = {50 72 69 6e 74 20 23 31 2c 20 76 61 72 48 74 6d 6c 28 22 32 69 6d 71 67 22 29 } //1 Print #1, varHtml("2imqg")
		$a_01_3 = {66 6f 72 50 72 6f 63 20 3d 20 52 65 70 6c 61 63 65 28 63 6f 72 65 48 74 6d 6c 43 6f 72 65 2c 20 76 61 72 43 6f 72 65 46 6f 72 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 29 } //1 forProc = Replace(coreHtmlCore, varCoreFor, vbNullString)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}