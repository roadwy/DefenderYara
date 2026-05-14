
rule Trojan_BAT_Barys_SLWR_MTB{
	meta:
		description = "Trojan:BAT/Barys.SLWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 7e 42 00 00 0a 28 1a 00 00 06 26 72 cd 0a 00 70 03 28 48 00 00 0a 72 db 0a 00 70 28 49 00 00 0a 1b 18 28 08 00 00 06 28 1c 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}