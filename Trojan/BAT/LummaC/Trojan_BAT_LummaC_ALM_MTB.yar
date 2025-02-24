
rule Trojan_BAT_LummaC_ALM_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 56 4d e4 eb f7 61 9b 49 c4 d4 52 2a 2c 43 6e b6 5b be 1e fc f9 36 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LummaC_ALM_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1d 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LummaC_ALM_MTB_3{
	meta:
		description = "Trojan:BAT/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 02 16 09 16 09 8e 69 28 ?? 00 00 0a 06 09 6f ?? 00 00 0a 02 8e 69 09 8e 69 59 8d ?? 00 00 01 13 04 02 09 8e 69 11 04 16 11 04 8e 69 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LummaC_ALM_MTB_4{
	meta:
		description = "Trojan:BAT/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 04 06 09 06 08 91 9c 06 08 11 04 9c 08 17 58 } //3
		$a_01_1 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1c 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}