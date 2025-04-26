
rule Adware_AndroidOS_Viser_A_MTB{
	meta:
		description = "Adware:AndroidOS/Viser.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 76 73 65 72 76 2e 6d 6f 62 69 2f 64 65 6c 69 76 65 72 79 2f 74 69 2e 70 68 70 } //10 .vserv.mobi/delivery/ti.php
		$a_01_1 = {2e 76 73 65 72 76 2e 6d 6f 62 69 2f 74 65 73 74 2f 74 69 2e 70 68 70 } //10 .vserv.mobi/test/ti.php
		$a_01_2 = {2f 56 73 65 72 76 41 64 } //1 /VservAd
		$a_01_3 = {6d 75 73 74 53 65 65 41 64 4d 73 67 } //1 mustSeeAdMsg
		$a_01_4 = {63 61 6c 6c 4b 69 6c 6c 50 72 6f 63 65 73 73 } //1 callKillProcess
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}