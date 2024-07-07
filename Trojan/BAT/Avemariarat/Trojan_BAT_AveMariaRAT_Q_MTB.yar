
rule Trojan_BAT_AveMariaRAT_Q_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {91 61 07 11 } //2
		$a_01_1 = {5d 59 d2 9c 11 } //2
		$a_01_2 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 ResourceManager
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}