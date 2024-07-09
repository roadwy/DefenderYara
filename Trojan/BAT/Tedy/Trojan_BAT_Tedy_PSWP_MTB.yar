
rule Trojan_BAT_Tedy_PSWP_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSWP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 02 00 00 06 7e 01 00 00 04 72 09 00 00 70 28 ?? 00 00 0a 72 1d 00 00 70 28 ?? 00 00 0a 72 09 00 00 70 28 ?? 00 00 0a 72 a1 00 00 70 28 ?? 00 00 0a 6f 03 00 00 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}