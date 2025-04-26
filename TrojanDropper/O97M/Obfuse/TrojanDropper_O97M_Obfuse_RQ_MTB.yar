
rule TrojanDropper_O97M_Obfuse_RQ_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.RQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 42 6c 6f 62 65 72 73 2e 76 62 73 22 } //1 Open "C:\ProgramData\Blobers.vbs"
		$a_00_1 = {57 72 69 74 69 6e 67 20 63 6f 64 65 20 74 68 61 74 20 77 6f 72 6b 73 20 6f 6e 20 62 6f 74 68 20 33 32 2d 62 69 74 20 61 6e 64 20 36 34 2d 62 69 74 20 4f 66 66 69 63 65 } //1 Writing code that works on both 32-bit and 64-bit Office
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 58 4d 4c 53 61 76 65 54 68 72 6f 75 67 68 58 53 4c 54 29 } //1 CreateObject(ThisDocument.XMLSaveThroughXSLT)
		$a_00_3 = {42 72 65 6d 65 6e 2e 45 78 65 63 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 } //1 Bremen.Exec ThisDocument.DefaultTargetFrame
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}