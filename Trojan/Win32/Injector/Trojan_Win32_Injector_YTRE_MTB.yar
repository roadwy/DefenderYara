
rule Trojan_Win32_Injector_YTRE_MTB{
	meta:
		description = "Trojan:Win32/Injector.YTRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 4d 4d 3a 44 6f 63 75 6d 65 6e 74 49 44 3e 61 64 6f 62 65 3a 64 6f 63 69 64 3a 70 68 6f 74 6f 73 68 6f 70 3a 65 34 61 33 66 39 33 31 2d 36 32 37 65 2d 31 31 64 63 2d 62 61 38 31 2d 39 62 66 62 33 63 63 34 63 62 64 66 3c 2f 78 61 70 4d 4d } //00 00  pMM:DocumentID>adobe:docid:photoshop:e4a3f931-627e-11dc-ba81-9bfb3cc4cbdf</xapMM
	condition:
		any of ($a_*)
 
}