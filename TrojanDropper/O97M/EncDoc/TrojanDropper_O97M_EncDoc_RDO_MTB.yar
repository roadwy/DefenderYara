
rule TrojanDropper_O97M_EncDoc_RDO_MTB{
	meta:
		description = "TrojanDropper:O97M/EncDoc.RDO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 5c 74 76 6b 71 6a 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 2e 6d 2e 2f 6b 6a 2e 22 29 2c 66 61 6c 73 65 2e 73 65 6e 64 3d 2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 69 66 2e 73 74 61 74 75 73 3d 32 30 30 74 68 65 6e 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 2e 6f 70 65 6e 2e 74 79 70 65 3d 2e 77 72 69 74 65 2e 73 61 76 65 74 6f 66 69 6c 65 } //1 =createobject("microsoft.xmlhttp")set=createobject("shell.application")=specialpath+("\tvkqj.").open"get",("h://.m./kj."),false.send=.responsebodyif.status=200thenset=createobject("adodb.stream").open.type=.write.savetofile
	condition:
		((#a_01_0  & 1)*1) >=1
 
}