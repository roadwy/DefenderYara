
rule TrojanDownloader_O97M_AgentTesla_PDOG_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.PDOG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 6d 6f 6e 65 79 63 6f 75 6e 74 2e 75 78 2b 6d 6f 6e 65 79 63 6f 75 6e 74 2e 74 72 2b 6d 6f 6e 73 74 65 72 63 6f 6d 69 6e 67 2e 7a 2b 6b 6f 6e 2e 64 2b 6c 75 6e 2e 6f 70 65 6e 6d 61 72 6b 65 74 31 32 34 35 2b 6c 75 6e 2e 78 78 78 2b 73 68 6f 77 6f 66 66 2e 6b 6f 6e 73 61 2b 73 68 6f 77 6f 66 66 2e 74 } //1 =moneycount.ux+moneycount.tr+monstercoming.z+kon.d+lun.openmarket1245+lun.xxx+showoff.konsa+showoff.t
		$a_01_1 = {6d 73 67 62 6f 78 22 6f 66 66 69 63 65 65 72 72 6f 72 21 21 21 22 3a 63 61 6c 6c 73 68 65 6c 6c 28 73 68 6f 72 29 65 6e 64 73 75 62 } //1 msgbox"officeerror!!!":callshell(shor)endsub
		$a_01_2 = {6b 6f 6e 73 61 28 29 61 73 73 74 72 69 6e 67 6b 6f 6e 73 61 3d 74 65 78 74 66 69 6c 65 70 61 72 74 2e 73 74 75 66 66 2e 74 61 67 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 74 28 29 } //1 konsa()asstringkonsa=textfilepart.stuff.tagendfunctionfunctiont()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}