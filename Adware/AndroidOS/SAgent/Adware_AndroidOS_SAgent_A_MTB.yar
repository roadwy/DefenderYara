
rule Adware_AndroidOS_SAgent_A_MTB{
	meta:
		description = "Adware:AndroidOS/SAgent.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 70 61 73 61 6e 2f 56 69 64 65 6f 5f 4c 69 73 74 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  com/appasan/Video_List/MainActivity
		$a_01_1 = {67 6f 54 6f 56 69 73 69 74 73 61 7a } //01 00  goToVisitsaz
		$a_01_2 = {69 63 61 6e 68 61 7a 69 70 2e 63 6f 6d } //01 00  icanhazip.com
		$a_01_3 = {73 65 74 41 64 4c 69 73 74 65 6e 65 72 } //01 00  setAdListener
		$a_01_4 = {2f 6d 6e 74 2f 73 64 63 61 72 64 2f 44 6f 77 6e 6c 6f 61 64 2f } //00 00  /mnt/sdcard/Download/
	condition:
		any of ($a_*)
 
}