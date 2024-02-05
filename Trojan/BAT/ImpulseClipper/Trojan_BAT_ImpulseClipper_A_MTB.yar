
rule Trojan_BAT_ImpulseClipper_A_MTB{
	meta:
		description = "Trojan:BAT/ImpulseClipper.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 65 67 53 76 63 2e 50 72 6f 70 65 72 74 69 65 73 } //02 00 
		$a_01_1 = {52 65 67 53 76 63 2e 52 65 67 53 76 63 2e 72 65 73 6f 75 72 63 65 73 } //02 00 
		$a_01_2 = {49 6d 70 75 6c 73 65 43 6c 69 70 70 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_3 = {43 6c 69 70 62 6f 61 72 64 } //01 00 
		$a_01_4 = {4d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}