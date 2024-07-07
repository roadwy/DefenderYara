
rule Trojan_BAT_AgentTesla_NFU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {03 02 7b 6f 00 00 04 04 02 7b 6f 00 00 04 6f 32 01 00 0a 5d 6f 33 01 00 0a 61 d2 2a } //1
		$a_01_1 = {57 d7 a2 3f 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 af 00 00 00 14 00 00 00 8e 00 00 00 7a 00 00 00 6c 00 00 00 02 00 00 00 4c 01 00 00 13 } //1
		$a_81_2 = {4f 70 74 69 6f 6e 73 7c 2a 2e 62 75 6c 6b 70 64 66 } //1 Options|*.bulkpdf
		$a_81_3 = {72 74 62 4c 69 62 72 61 72 69 65 73 2e 54 65 78 74 } //1 rtbLibraries.Text
		$a_81_4 = {6f 70 74 69 6f 6e 73 2e 74 78 74 } //1 options.txt
		$a_81_5 = {42 75 6c 6b 50 44 46 2e 65 78 65 } //1 BulkPDF.exe
		$a_81_6 = {45 78 63 65 70 74 69 6f 6e 50 44 46 46 69 6c 65 41 6c 72 65 61 64 79 45 78 69 73 74 73 41 6e 64 49 6e 55 73 65 } //1 ExceptionPDFFileAlreadyExistsAndInUse
		$a_81_7 = {42 75 6c 6b 50 44 46 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 BulkPDF.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}