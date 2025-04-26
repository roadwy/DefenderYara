
rule Trojan_AndroidOS_Spynote_PY{
	meta:
		description = "Trojan:AndroidOS/Spynote.PY,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 0a 00 00 "
		
	strings :
		$a_01_0 = {72 75 67 62 79 2e 62 69 62 6c 65 2e 63 6f 73 74 6d } //1 rugby.bible.costm
		$a_01_1 = {77 77 77 2e 73 69 6e 67 61 70 6f 72 65 2d 6d 61 6c 6c 2e 63 6f 6d } //1 www.singapore-mall.com
		$a_01_2 = {4d 54 55 30 4c 6a 4d 35 4c 6a 45 31 4f 43 34 7a 4d 77 } //1 MTU0LjM5LjE1OC4zMw
		$a_01_3 = {63 65 6e 74 65 72 2e 62 65 61 73 74 61 6c 69 74 79 2e 77 61 6e 2e 52 45 43 4f 52 44 } //1 center.beastality.wan.RECORD
		$a_01_4 = {4d 54 55 30 4c 6a 4d 35 4c 6a 45 31 4f 43 34 7a 4f 41 3d 3d } //1 MTU0LjM5LjE1OC4zOA==
		$a_01_5 = {63 6f 6e 66 6c 69 63 74 73 73 31 } //1 conflictss1
		$a_01_6 = {61 6c 74 65 72 65 64 2e 69 6e 64 65 70 65 6e 64 65 6e 74 6c 79 2e 6f 70 74 69 6f 6e 61 6c 2e 52 45 43 4f 52 44 } //1 altered.independently.optional.RECORD
		$a_01_7 = {73 72 69 2e 73 75 72 76 69 76 6f 72 73 2e 63 6f 6e 63 65 72 74 2e 52 45 43 4f 52 44 } //1 sri.survivors.concert.RECORD
		$a_01_8 = {63 61 72 74 72 69 64 67 65 2e 73 75 6c 6c 69 76 61 6e 2e 70 75 73 73 79 } //1 cartridge.sullivan.pussy
		$a_01_9 = {4d 54 63 31 4c 6a 51 78 4c 6a 49 78 4c 6a 51 30 } //1 MTc1LjQxLjIxLjQ0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=2
 
}