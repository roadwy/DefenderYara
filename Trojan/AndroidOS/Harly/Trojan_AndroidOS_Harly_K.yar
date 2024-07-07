
rule Trojan_AndroidOS_Harly_K{
	meta:
		description = "Trojan:AndroidOS/Harly.K,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 75 6e 65 72 2f 73 70 61 72 72 6f 77 2f 76 6f 69 63 65 } //1 Lcom/uner/sparrow/voice
		$a_01_1 = {64 65 6c 65 74 69 6e 67 20 66 69 6c 65 20 61 6e 64 20 63 72 65 61 74 69 6e 67 20 6e 65 77 20 64 69 72 65 63 74 6f 72 79 } //1 deleting file and creating new directory
		$a_01_2 = {71 75 6c 63 6e 64 35 42 41 4f 63 32 4e 69 78 55 46 6d 72 50 67 78 2b 44 41 44 31 56 2f 68 70 6f 4b 34 6e 6f 77 48 4f 42 62 67 3d } //1 qulcnd5BAOc2NixUFmrPgx+DAD1V/hpoK4nowHOBbg=
		$a_01_3 = {72 65 77 61 72 64 5f 76 69 64 65 6f 3d } //1 reward_video=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}