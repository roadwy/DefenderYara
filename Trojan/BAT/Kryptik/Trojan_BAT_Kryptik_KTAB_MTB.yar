
rule Trojan_BAT_Kryptik_KTAB_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.KTAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 65 70 65 6c 4c 65 65 67 } //2 LepelLeeg
		$a_01_1 = {52 65 6d 6f 76 65 44 61 74 53 68 69 74 } //2 RemoveDatShit
		$a_01_2 = {56 65 72 6b 6c 65 70 65 72 69 6a } //3 Verkleperij
		$a_01_3 = {00 50 61 79 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=9
 
}