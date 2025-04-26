
rule TrojanDownloader_O97M_Powdow_PDOB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDOB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 73 6f 63 69 61 6c 77 6f 72 6b 32 31 2e 75 78 2b 73 6f 63 69 61 6c 77 6f 72 6b 32 31 2e 74 72 2b 62 6f 72 69 6e 67 64 61 79 2e 7a 2b 62 6f 72 69 6e 67 64 61 79 2e 64 2b 68 69 2e 6f 70 65 6e 6d 61 72 6b 65 74 31 32 34 35 2b 68 69 2e 78 78 78 2b 68 69 2e 6b 6f 6e 73 61 2b 68 69 2e 74 } //1 =socialwork21.ux+socialwork21.tr+boringday.z+boringday.d+hi.openmarket1245+hi.xxx+hi.konsa+hi.t
		$a_01_1 = {6d 73 67 62 6f 78 22 65 72 72 6f 72 6f 63 63 75 72 65 64 21 21 21 22 3a 5f 63 61 6c 6c 73 68 65 6c 6c 21 28 6d 6f 6e 65 79 63 61 6c 63 75 6c 61 74 69 6f 6e 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 msgbox"erroroccured!!!":_callshell!(moneycalculation)endfunction
		$a_01_2 = {6d 61 72 6b 65 74 31 32 34 35 3d 74 65 78 74 66 69 6c 65 70 61 72 74 2e 6d 6f 73 75 66 31 2e 74 61 67 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 78 78 78 28 29 } //1 market1245=textfilepart.mosuf1.tagendfunctionfunctionxxx()
		$a_01_3 = {66 75 6e 63 74 69 6f 6e 6b 6f 6e 73 61 28 29 61 73 73 74 72 69 6e 67 6b 6f 6e 73 61 3d 74 65 78 74 66 69 6c 65 70 61 72 74 2e 73 74 75 66 66 2e 74 61 67 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 74 28 29 } //1 functionkonsa()asstringkonsa=textfilepart.stuff.tagendfunctionfunctiont()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}