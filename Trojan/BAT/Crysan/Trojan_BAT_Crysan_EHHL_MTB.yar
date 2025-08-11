
rule Trojan_BAT_Crysan_EHHL_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EHHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {11 07 11 0e 11 10 11 0e 6c 11 10 6c ?? ?? ?? ?? ?? 11 0e 11 10 d6 17 d6 6c 5b ?? ?? ?? ?? ?? 11 10 17 d6 13 10 11 10 11 0f 31 d5 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}