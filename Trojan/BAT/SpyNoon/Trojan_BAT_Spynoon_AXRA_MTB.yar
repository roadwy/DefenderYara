
rule Trojan_BAT_Spynoon_AXRA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AXRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 11 09 6f ?? ?? 00 0a 13 0a 11 06 11 05 6f ?? ?? 00 0a 59 13 0b 11 0b 19 32 3d 19 8d ?? 00 00 01 25 16 12 0a 28 ?? ?? 00 0a 9c 25 17 12 0a 28 ?? ?? 00 0a 9c 25 18 12 0a 28 ?? ?? 00 0a 9c 13 0c 08 } //5
		$a_03_1 = {11 05 11 0c 6f ?? ?? 00 0a 2b 48 11 0b 16 31 43 19 8d ?? 00 00 01 25 16 12 0a 28 ?? ?? 00 0a 9c 25 17 12 0a 28 ?? ?? 00 0a 9c 25 18 12 0a 28 ?? ?? 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}