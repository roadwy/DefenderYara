
rule Trojan_BAT_Convagent_SPBF_MTB{
	meta:
		description = "Trojan:BAT/Convagent.SPBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 29 00 06 08 8f 0c 00 00 01 25 71 0c 00 00 01 72 4b 00 00 70 08 1f 6e 5d 6f ?? 00 00 0a d2 61 d2 81 0c 00 00 01 00 08 17 58 0c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}