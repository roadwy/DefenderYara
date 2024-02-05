
rule Trojan_BAT_Ratasafa_NYP_MTB{
	meta:
		description = "Trojan:BAT/Ratasafa.NYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 54 01 00 0a 0d 08 09 28 ce 01 00 06 09 16 6a 6f 55 01 00 0a 09 13 04 de 1c } //01 00 
		$a_01_1 = {57 1f b6 0b 09 1f 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 c4 00 00 00 59 00 00 00 e9 00 00 00 d5 01 00 00 3c 01 00 00 47 00 00 00 76 01 00 00 16 00 00 00 fa 00 00 00 42 } //01 00 
		$a_81_2 = {2f 42 6c 61 63 6b 4e 6f 74 65 70 61 64 3b 63 6f 6d 70 6f 6e 65 6e 74 2f 61 70 70 2e 78 61 6d 6c } //01 00 
		$a_81_3 = {42 6c 61 63 6b 4e 6f 74 65 70 61 64 2e 65 78 65 } //01 00 
		$a_01_4 = {53 61 76 61 67 65 64 2e 42 6c 61 63 6b 4e 6f 74 65 70 61 64 2e 50 72 } //00 00 
	condition:
		any of ($a_*)
 
}