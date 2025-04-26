
rule Trojan_BAT_Zusy_HNR_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 00 70 00 68 00 70 00 00 0d 76 00 61 00 6c 00 75 00 65 00 31 00 00 0d 76 00 61 00 6c 00 75 00 65 00 32 00 00 ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1
		$a_01_1 = {2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}