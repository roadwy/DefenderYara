
rule Backdoor_BAT_Crysan_AW_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {07 1f 10 5d 91 61 07 20 ff 00 00 00 5d d1 61 d1 9d 07 17 58 0b 07 } //03 00 
		$a_81_1 = {6d 69 6c 65 73 66 69 6e 64 65 72 } //03 00 
		$a_81_2 = {64 75 63 6b 63 68 6f 69 63 65 73 65 6c 65 63 74 6f 72 } //03 00 
		$a_81_3 = {62 75 72 63 61 73 74 35 } //00 00 
	condition:
		any of ($a_*)
 
}