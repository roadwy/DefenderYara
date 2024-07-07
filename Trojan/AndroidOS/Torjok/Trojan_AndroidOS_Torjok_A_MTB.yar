
rule Trojan_AndroidOS_Torjok_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Torjok.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 2d 67 6f 61 70 6b } //1 p-goapk
		$a_01_1 = {6b 6a 73 31 32 33 2e 73 69 6e 61 61 70 70 2e 63 6f 6d 2f 73 64 6b 63 66 67 2e 70 68 70 3f } //1 kjs123.sinaapp.com/sdkcfg.php?
		$a_01_2 = {2f 73 64 63 2f 6e 65 77 69 6e 69 74 35 2e 70 68 70 3f } //1 /sdc/newinit5.php?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}