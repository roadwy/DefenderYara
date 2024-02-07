
rule TrojanDropper_O97M_EncDoc_PDA_MTB{
	meta:
		description = "TrojanDropper:O97M/EncDoc.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 75 6d 63 64 72 2e 6f 70 65 6e 28 75 77 66 6c 79 2b 22 5c 6c 73 75 7a 6b 2e 6a 22 2b 22 73 22 29 65 6e 64 73 75 62 73 75 62 } //01 00  cumcdr.open(uwfly+"\lsuzk.j"+"s")endsubsub
		$a_01_1 = {26 61 63 74 69 76 65 73 68 65 65 74 2e 6f 6c 65 6f 62 6a 65 63 74 73 28 31 29 2e 63 6f 70 79 73 65 74 63 75 6d 63 64 72 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 6d 65 72 6d 6b 64 28 29 29 } //01 00  &activesheet.oleobjects(1).copysetcumcdr=createobject(mermkd())
		$a_01_2 = {7a 73 73 62 3d 22 5c 61 70 70 64 61 74 61 5c 72 6f 61 6d 69 6e 67 22 68 66 7a 6a 72 3d 70 74 62 6f 6b 65 63 2b 76 76 30 65 64 64 2e } //00 00  zssb="\appdata\roaming"hfzjr=ptbokec+vv0edd.
	condition:
		any of ($a_*)
 
}