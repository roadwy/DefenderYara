
rule Trojan_BAT_Heracles_GZX_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 1b 6a 28 ?? ?? ?? 0a 1f 40 12 05 28 ?? ?? ?? 06 26 1c } //5
		$a_03_1 = {72 4b 00 00 70 0c 28 ?? ?? ?? 0a 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 09 28 ?? ?? ?? 0a 07 09 28 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}