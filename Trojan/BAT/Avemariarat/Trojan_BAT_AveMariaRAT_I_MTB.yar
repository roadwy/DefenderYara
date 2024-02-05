
rule Trojan_BAT_AveMariaRAT_I_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b1 00 00 00 1e 00 00 00 8a 02 00 00 62 07 } //02 00 
		$a_01_1 = {51 75 61 6e 4c 79 43 75 61 48 61 6e 67 54 68 75 43 75 6e 67 53 69 65 75 50 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}