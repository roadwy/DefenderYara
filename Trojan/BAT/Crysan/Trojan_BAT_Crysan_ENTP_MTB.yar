
rule Trojan_BAT_Crysan_ENTP_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ENTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 08 03 08 91 08 04 ?? ?? ?? ?? ?? 9c 08 17 d6 0c 08 07 31 eb } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}