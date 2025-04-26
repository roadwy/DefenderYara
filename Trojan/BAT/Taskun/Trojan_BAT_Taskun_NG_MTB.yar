
rule Trojan_BAT_Taskun_NG_MTB{
	meta:
		description = "Trojan:BAT/Taskun.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 38 61 36 61 38 35 66 2d 31 32 66 39 2d 34 33 31 64 2d 61 31 32 36 2d 63 39 34 61 64 63 62 39 64 32 39 36 } //3 c8a6a85f-12f9-431d-a126-c94adcb9d296
		$a_81_1 = {6b 61 6e 6a 69 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d } //1 kanjiToolStripMenuItem
		$a_81_2 = {64 69 73 70 6c 61 79 46 75 72 69 67 61 6e 61 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d } //1 displayFuriganaToolStripMenuItem
		$a_81_3 = {62 74 6e 4e 65 78 74 4b 61 6e 6a 69 } //1 btnNextKanji
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=6
 
}