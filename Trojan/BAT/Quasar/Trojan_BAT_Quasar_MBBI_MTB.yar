
rule Trojan_BAT_Quasar_MBBI_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MBBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 09 11 00 11 05 11 00 91 11 0a 61 d2 9c } //01 00 
		$a_01_1 = {6a 00 75 00 73 00 74 00 6e 00 6f 00 72 00 6d 00 61 00 6c 00 73 00 69 00 74 00 65 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 2f 00 53 00 79 00 73 00 74 00 65 00 6d 00 45 00 6e 00 76 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 } //01 00  justnormalsite.ddns.net/SystemEnv/uploads/
		$a_01_2 = {4f 00 76 00 79 00 79 00 76 00 69 00 6d 00 68 00 61 00 6a } //00 00 
	condition:
		any of ($a_*)
 
}