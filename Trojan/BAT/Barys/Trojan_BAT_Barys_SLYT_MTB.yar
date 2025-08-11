
rule Trojan_BAT_Barys_SLYT_MTB{
	meta:
		description = "Trojan:BAT/Barys.SLYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 39 16 00 00 00 17 8d 01 00 00 01 0d 09 16 16 8d 18 00 00 01 a2 09 38 01 00 00 00 14 0c 07 14 08 6f 16 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}