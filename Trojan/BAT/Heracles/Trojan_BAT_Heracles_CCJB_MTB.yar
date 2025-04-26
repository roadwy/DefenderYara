
rule Trojan_BAT_Heracles_CCJB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 6b 7a 39 56 63 6c 4d 63 75 54 4f 4d 73 34 42 34 49 37 49 49 41 3d 3d } //5 Tkz9VclMcuTOMs4B4I7IIA==
		$a_01_1 = {52 50 78 69 48 46 47 36 75 35 4d 50 39 42 34 2b 66 7a 31 6d 6d 51 3d 3d } //1 RPxiHFG6u5MP9B4+fz1mmQ==
		$a_01_2 = {68 66 70 41 71 6c 45 4f 51 44 34 4c 66 42 73 37 4b 32 73 50 34 77 3d 3d } //1 hfpAqlEOQD4LfBs7K2sP4w==
		$a_01_3 = {68 32 4c 78 71 64 38 30 54 6d 75 4d 39 70 69 69 42 74 72 6c 57 51 3d 3d } //1 h2Lxqd80TmuM9piiBtrlWQ==
		$a_01_4 = {66 4f 4f 2b 38 65 55 49 30 62 46 6d 44 57 79 72 35 7a 71 59 46 67 3d 3d } //1 fOO+8eUI0bFmDWyr5zqYFg==
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}