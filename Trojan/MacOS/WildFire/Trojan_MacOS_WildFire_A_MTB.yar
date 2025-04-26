
rule Trojan_MacOS_WildFire_A_MTB{
	meta:
		description = "Trojan:MacOS/WildFire.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 6e 65 76 65 72 47 6f 6e 6e 61 47 69 76 65 59 6f 75 55 70 } //1 _neverGonnaGiveYouUp
		$a_01_1 = {5f 6e 65 76 65 72 47 6f 6e 6e 61 52 75 6e 41 72 6f 75 6e 64 41 6e 64 44 65 73 65 72 74 59 6f 75 } //1 _neverGonnaRunAroundAndDesertYou
		$a_01_2 = {5f 6e 65 76 65 72 47 6f 6e 6e 61 4c 65 74 59 6f 75 44 6f 77 6e } //1 _neverGonnaLetYouDown
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}