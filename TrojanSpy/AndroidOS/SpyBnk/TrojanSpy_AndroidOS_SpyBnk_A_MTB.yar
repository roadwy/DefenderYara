
rule TrojanSpy_AndroidOS_SpyBnk_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyBnk.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 69 62 63 68 65 2e 61 73 70 61 72 64 70 72 6f 6a 65 63 74 2e 61 70 70 } //1 com.sibche.aspardproject.app
		$a_00_1 = {53 50 49 44 45 52 5f 57 39 38 39 38 } //1 SPIDER_W9898
		$a_00_2 = {63 6f 6d 2f 61 73 61 6e 70 61 72 64 61 6b 68 74 2f 6a 6f 63 6b 65 72 62 6c 6f 63 6b } //1 com/asanpardakht/jockerblock
		$a_00_3 = {6e 65 78 68 61 63 6b } //1 nexhack
		$a_00_4 = {48 61 63 6b 65 64 20 6e 75 6d 62 61 72 20 68 68 65 6c 70 20 63 68 61 72 79 74 79 } //1 Hacked numbar hhelp charyty
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}