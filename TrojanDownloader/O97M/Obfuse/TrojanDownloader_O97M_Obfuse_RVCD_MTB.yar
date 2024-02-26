
rule TrojanDownloader_O97M_Obfuse_RVCD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVCD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 63 75 6d 65 6e 74 5f 63 6c 6f 73 65 28 29 6f 6e 65 72 72 6f 72 72 65 73 75 6d 65 6e 65 78 74 68 61 6c 6c 65 79 76 3d 68 61 6c 6c 65 79 76 2b 22 72 67 6c 74 69 67 7a 73 79 77 64 71 7a 32 6f 6e 63 6b 39 75 69 65 76 79 63 6d 39 79 69 66 6a 6c 63 33 76 74 7a 73 62 6f 7a 78 68 30 64 71 6f 6e 63 6e 62 79 62 33 7a 6c 63 68 6e 78 70 73 69 6c 76 30 31 76 6a } //01 00  document_close()onerrorresumenexthalleyv=halleyv+"rgltigzsywdqz2onck9uievycm9yifjlc3vtzsbozxh0dqoncnbyb3zlchnxpsilv01vj
		$a_01_1 = {72 65 70 6c 61 63 65 28 6d 65 73 73 65 6e 67 65 72 74 77 32 2c 22 3a 22 2c 76 62 63 72 6c 66 29 62 65 6c 6f 6e 67 69 6e 67 73 7a 77 30 3d 6d 65 73 73 65 6e 67 65 72 74 77 32 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00  replace(messengertw2,":",vbcrlf)belongingszw0=messengertw2endfunction
		$a_01_2 = {62 65 6c 6f 6e 67 69 6e 67 73 7a 77 30 28 70 65 74 72 6f 6c 6b 78 6f 29 73 65 74 69 6e 63 6f 6d 65 78 6b 34 3d 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 76 62 70 72 6f 6a 65 63 74 2e 76 62 63 6f 6d 70 6f 6e 65 6e 74 73 2e 61 64 64 28 31 29 69 6e 63 6f 6d 65 78 6b 34 2e 63 6f 64 65 6d 6f 64 75 6c 65 2e 61 64 64 66 72 6f 6d 73 74 72 69 6e 67 72 61 74 65 73 78 70 77 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 61 70 70 6c 69 63 61 74 69 6f 6e 2e 72 75 6e } //00 00  belongingszw0(petrolkxo)setincomexk4=activedocument.vbproject.vbcomponents.add(1)incomexk4.codemodule.addfromstringratesxpwactivedocument.application.run
	condition:
		any of ($a_*)
 
}