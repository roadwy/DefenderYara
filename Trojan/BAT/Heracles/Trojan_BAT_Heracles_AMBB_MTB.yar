
rule Trojan_BAT_Heracles_AMBB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 11 00 11 02 93 20 ?? 00 00 00 61 02 61 d1 9d 20 } //1
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 47 65 6e 65 72 61 74 65 49 56 } //1 牃慥整敄牣灹潴r敇敮慲整噉
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}