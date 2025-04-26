
rule Trojan_BAT_Convagent_KAB_MTB{
	meta:
		description = "Trojan:BAT/Convagent.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 91 04 58 d2 0d 07 08 17 58 91 04 58 d2 13 04 07 08 11 04 9c 07 08 17 58 09 9c 08 18 58 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}