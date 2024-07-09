
rule Trojan_BAT_Crysan_KTS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.KTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 09 7e 03 00 00 04 11 09 7e 03 00 00 04 8e 69 5d 91 9e 11 09 17 58 13 09 11 09 72 cd 00 00 70 28 ?? ?? ?? 0a 32 d7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}