
rule Trojan_Win64_Tedy_MKI_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 84 24 30 02 00 00 48 05 90 13 00 00 48 89 44 24 48 48 8b 44 24 48 48 89 44 24 50 48 8b 44 24 50 48 89 44 24 30 48 8b 44 24 30 48 c7 00 00 00 00 00 48 8b 44 24 30 48 c7 40 08 00 00 00 00 48 8b 44 24 30 48 c7 40 10 } //20
		$a_01_1 = {6e 76 6d 6c 53 79 73 74 65 6d 47 65 74 44 72 69 76 65 72 56 65 72 73 69 6f 6e } //15 nvmlSystemGetDriverVersion
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}