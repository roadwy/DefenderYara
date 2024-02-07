
rule TrojanDownloader_O97M_EncDoc_PAQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 28 22 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 63 6d 64 2e 65 78 65 2f 76 2f 64 2f 63 22 22 73 65 74 73 6b 6b } //01 00  shell("c:\\windows\\system32\\cmd.exe/v/d/c""setskk
		$a_01_1 = {68 6c 6e 35 74 74 70 3a 27 3b 67 6c 6e 35 65 74 6f 62 6a 6c 6e 35 65 63 74 28 63 2b 64 2b 27 26 26 73 65 74 68 78 64 3d 6c 76 6d 78 64 6c 76 6d 78 64 74 38 36 35 66 } //01 00  hln5ttp:';gln5etobjln5ect(c+d+'&&sethxd=lvmxdlvmxdt865f
		$a_01_2 = {68 74 61 7c 73 74 61 72 74 21 70 78 21 21 75 6e 75 75 21 2e 68 74 61 22 22 22 29 2c 76 62 68 69 } //00 00  hta|start!px!!unuu!.hta"""),vbhi
	condition:
		any of ($a_*)
 
}