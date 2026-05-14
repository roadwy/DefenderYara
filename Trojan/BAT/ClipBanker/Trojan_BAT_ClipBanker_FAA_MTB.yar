
rule Trojan_BAT_ClipBanker_FAA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.FAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 08 91 1f 32 61 d1 9d 08 17 58 0c 08 06 8e 69 32 ec } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}