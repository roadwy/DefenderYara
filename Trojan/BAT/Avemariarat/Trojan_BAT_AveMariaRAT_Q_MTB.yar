
rule Trojan_BAT_AveMariaRAT_Q_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {91 61 07 11 } //02 00 
		$a_01_1 = {5d 59 d2 9c 11 } //01 00 
		$a_01_2 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //00 00  ResourceManager
	condition:
		any of ($a_*)
 
}