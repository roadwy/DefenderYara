
rule Trojan_BAT_Tedy_PSNB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 72 89 02 00 70 28 10 00 00 06 06 72 bb 02 00 70 72 07 03 00 70 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 72 0f 03 00 70 28 10 00 00 06 08 16 20 62 03 00 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 25 07 17 28 0b 00 00 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}