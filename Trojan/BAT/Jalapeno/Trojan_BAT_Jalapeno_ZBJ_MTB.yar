
rule Trojan_BAT_Jalapeno_ZBJ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 08 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 2d 15 12 04 28 ?? 00 00 0a 2d 0c 12 04 28 ?? 00 00 0a 16 fe 01 2b 01 16 13 05 11 05 2c 02 2b 71 12 04 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}