
rule Trojan_O97M_EncDoc_RED_MTB{
	meta:
		description = "Trojan:O97M/EncDoc.RED!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 62 75 66 42 6f 72 64 65 72 50 6f 69 6e 74 65 72 2e 68 74 61 22 } //1 = "explorer.exe c:\programdata\bufBorderPointer.hta"
		$a_03_1 = {53 65 74 20 [0-0f] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 0d 0a 90 1b 00 2e 65 78 65 63 20 70 28 67 65 74 77 63 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}