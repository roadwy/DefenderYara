
rule Trojan_BAT_DCRat_RDJ_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 47 78 44 55 72 35 75 52 72 62 57 32 58 39 59 63 54 49 64 55 6b 4d 69 35 45 } //1 SGxDUr5uRrbW2X9YcTIdUkMi5E
		$a_01_1 = {70 78 71 44 73 42 50 6d 70 30 6e 59 } //1 pxqDsBPmp0nY
		$a_01_2 = {24 54 52 24 34 45 } //1 $TR$4E
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}