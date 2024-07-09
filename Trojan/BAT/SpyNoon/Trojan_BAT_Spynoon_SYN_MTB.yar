
rule Trojan_BAT_Spynoon_SYN_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.SYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 91 2b 0e 07 25 17 59 1e 2d 13 26 16 fe 02 0c 2b 07 6f ?? ?? ?? 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}