
rule Backdoor_AndroidOS_Basdoor_E_MTB{
	meta:
		description = "Backdoor:AndroidOS/Basdoor.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 72 6c 2e 70 68 70 3f 61 70 70 3d 31 30 } //01 00  url.php?app=10
		$a_01_1 = {5f 67 65 74 65 77 61 79 75 72 6c } //01 00  _getewayurl
		$a_01_2 = {50 68 6f 6e 65 53 6d 73 } //01 00  PhoneSms
		$a_01_3 = {63 6f 6d 2e 6c 79 75 66 6f 2e 70 6c 61 79 } //01 00  com.lyufo.play
		$a_01_4 = {5f 6d 65 73 73 61 67 65 73 65 6e 74 } //00 00  _messagesent
	condition:
		any of ($a_*)
 
}