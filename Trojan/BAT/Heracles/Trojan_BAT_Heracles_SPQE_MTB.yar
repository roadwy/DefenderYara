
rule Trojan_BAT_Heracles_SPQE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 02 08 6f ?? ?? ?? 0a 06 08 06 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 00 08 17 58 0c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}