
rule Trojan_BAT_Convagent_PSJT_MTB{
	meta:
		description = "Trojan:BAT/Convagent.PSJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 8d 07 00 00 01 13 04 16 13 05 2b 22 08 28 08 00 00 0a 2d 1a 08 28 04 00 00 06 0a 11 04 11 05 06 1f 10 28 09 00 00 0a 9c 11 05 17 58 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}