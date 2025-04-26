
rule Trojan_BAT_SpyNoon_YJX_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.YJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 8d 14 00 00 01 25 16 1f 23 9d 28 ?? ?? ?? 0a 20 00 01 00 00 14 14 17 8d 57 00 00 01 25 16 02 a2 28 ?? ?? ?? 0a 74 59 00 00 01 0a 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}