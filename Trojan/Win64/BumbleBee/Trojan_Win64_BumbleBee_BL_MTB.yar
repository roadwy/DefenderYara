
rule Trojan_Win64_BumbleBee_BL_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a fc 49 01 80 ?? ?? ?? ?? 49 8b 80 ?? ?? ?? ?? 48 2d ?? ?? ?? ?? 48 31 81 ?? ?? ?? ?? 41 8d 4f ?? 41 8a 80 ?? ?? ?? ?? 40 d2 ef 34 ?? 40 22 f8 49 8b 80 ?? ?? ?? ?? 48 8b 88 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}