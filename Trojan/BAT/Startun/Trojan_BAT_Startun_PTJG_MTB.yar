
rule Trojan_BAT_Startun_PTJG_MTB{
	meta:
		description = "Trojan:BAT/Startun.PTJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 36 00 00 0a 13 05 73 37 00 00 0a 13 06 11 06 08 20 96 00 00 00 20 c8 00 00 00 6f 2c 00 00 0a 6a 28 ?? 00 00 06 6f 38 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}