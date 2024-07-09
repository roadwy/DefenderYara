
rule Trojan_BAT_Tiny_PTCK_MTB{
	meta:
		description = "Trojan:BAT/Tiny.PTCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2c 5a 00 00 06 28 ?? 00 00 0a 0c 08 6f 14 00 00 0a 0d 09 14 28 ?? 00 00 0a 13 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}