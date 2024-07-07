
rule TrojanDownloader_O97M_AgentTesla_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {22 74 70 3a 2f 2f 31 32 33 30 39 31 32 34 38 39 25 31 32 33 30 31 39 32 33 30 39 40 6a 2e 6d 70 2f 22 } //2 "tp://1230912489%1230192309@j.mp/"
		$a_00_1 = {22 74 70 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 6a 2e 6d 70 2f 22 } //2 "tp://1230948%1230948@j.mp/"
		$a_00_2 = {22 6a 64 61 73 64 76 6a 67 61 73 67 76 64 62 6a 68 61 73 64 6f 6b 22 } //2 "jdasdvjgasgvdbjhasdok"
		$a_00_3 = {22 32 33 62 62 73 64 61 6a 73 38 32 31 22 } //2 "23bbsdajs821"
		$a_00_4 = {3d 20 22 68 74 61 22 22 20 68 74 22 } //1 = "hta"" ht"
		$a_00_5 = {53 68 65 6c 6c 20 28 57 49 4e 57 4f 52 44 20 2b 20 4d 73 67 42 6f 78 4f 6c } //1 Shell (WINWORD + MsgBoxOl
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_AgentTesla_RVA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 73 68 65 6c 6c 21 28 74 65 78 74 66 69 6c 65 73 74 75 66 66 6f 6e 6c 79 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 callshell!(textfilestuffonly)endfunction
		$a_01_1 = {3d 6f 70 65 72 61 2e 78 2b 6f 70 65 72 61 2e 79 2b 74 65 78 74 66 69 6c 65 66 6f 72 79 6f 75 2e 7a 2b 74 65 78 74 66 69 6c 65 66 6f 72 79 6f 75 2e 64 2b 68 69 2e 6f 70 65 6e 6d 61 72 6b 65 74 2b 68 69 2e 78 78 78 2b 68 69 2e 6b 2b 68 69 2e 74 } //1 =opera.x+opera.y+textfileforyou.z+textfileforyou.d+hi.openmarket+hi.xxx+hi.k+hi.t
		$a_01_2 = {74 65 78 74 66 69 6c 65 73 74 75 66 66 2e 6d 6f 73 75 66 2e 74 61 67 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 textfilestuff.mosuf.tagendfunction
		$a_01_3 = {61 75 74 6f 5f 63 6c 6f 73 65 28 29 } //1 auto_close()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}