
rule TrojanDownloader_O97M_Obfuse_BC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 61 73 20 3d 20 52 65 70 6c 61 63 65 28 22 53 79 73 74 65 6d 43 6f 6d 70 6f 6e 65 6e 74 4d 6f 64 65 6c 54 79 70 65 44 65 73 63 72 69 70 74 6f 72 54 79 70 65 44 65 73 63 72 69 70 74 6f 72 49 6e 74 65 72 66 61 63 65 73 68 74 74 70 3a 2f 2f 37 64 65 33 2e 73 68 61 6e 64 6f 77 2e 72 75 2f 44 72 75 6d 68 65 61 64 73 2e 65 78 65 53 79 73 74 65 6d 43 6f 6d 70 6f 6e 65 6e 74 4d 6f 64 65 6c 54 79 70 65 44 65 73 63 72 69 70 74 6f 72 54 79 70 65 44 65 73 63 72 69 70 74 6f 72 49 6e 74 65 72 66 61 63 65 73 22 2c 20 22 53 79 73 74 65 6d 43 6f 6d 70 6f 6e 65 6e 74 4d 6f 64 65 6c 54 79 70 65 44 65 73 63 72 69 70 74 6f 72 54 79 70 65 44 65 73 63 72 69 70 74 6f 72 49 6e 74 65 72 66 61 63 65 73 22 2c 20 22 22 29 } //1 das = Replace("SystemComponentModelTypeDescriptorTypeDescriptorInterfaceshttp://7de3.shandow.ru/Drumheads.exeSystemComponentModelTypeDescriptorTypeDescriptorInterfaces", "SystemComponentModelTypeDescriptorTypeDescriptorInterfaces", "")
		$a_00_1 = {73 61 73 20 3d 20 52 65 70 6c 61 63 65 28 22 6d 4e 65 74 43 68 75 6e 6b 50 61 72 73 65 72 52 65 61 64 53 74 61 74 65 71 53 79 73 74 65 6d 43 6f 6d 70 6f 6e 65 6e 74 4d 6f 64 65 6c 44 65 73 69 67 6e 53 74 61 6e 64 61 72 64 43 6f 6d 6d 61 6e 64 73 56 53 53 74 61 6e 64 61 72 64 43 6f 6d 6d 61 6e 64 73 45 2e 65 6d 4e 65 74 43 68 75 6e 6b 50 61 72 73 65 72 52 65 61 64 53 74 61 74 65 71 78 65 22 2c 20 22 6d 4e 65 74 43 68 75 6e 6b 50 61 72 73 65 72 52 65 61 64 53 74 61 74 65 71 22 2c 20 22 22 29 } //1 sas = Replace("mNetChunkParserReadStateqSystemComponentModelDesignStandardCommandsVSStandardCommandsE.emNetChunkParserReadStateqxe", "mNetChunkParserReadStateq", "")
		$a_00_2 = {6c 72 20 3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 28 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 5f } //1 lr = CreateProcess(vbNullString, _
		$a_00_3 = {43 6d 64 4c 69 6e 65 20 3d 20 22 22 22 22 20 26 20 46 69 6c 65 6e 61 6d 65 20 26 20 22 22 22 22 } //1 CmdLine = """" & Filename & """"
		$a_00_4 = {53 79 73 74 65 6d 44 61 74 61 53 71 6c 43 6c 69 65 6e 74 53 71 6c 43 6f 6c 75 6d 6e 45 6e 63 72 79 70 74 69 6f 6e 43 73 70 50 72 6f 76 69 64 65 72 62 20 3d 20 6c 72 } //1 SystemDataSqlClientSqlColumnEncryptionCspProviderb = lr
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}