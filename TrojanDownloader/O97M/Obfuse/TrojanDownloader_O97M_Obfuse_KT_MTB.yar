
rule TrojanDownloader_O97M_Obfuse_KT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 6f 63 2e 6c 72 75 63 5c 70 6d 65 74 5c 73 77 6f 64 6e 69 77 5c 3a 63 } //1 moc.lruc\pmet\swodniw\:c
		$a_00_1 = {65 78 65 2e 6e 69 6d 64 61 73 74 69 62 5c 32 33 6d 65 74 73 79 73 5c 73 77 6f 64 6e 69 77 5c 3a 63 } //1 exe.nimdastib\23metsys\swodniw\:c
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}