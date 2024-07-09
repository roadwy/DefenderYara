
rule Trojan_Win64_Zenlod_RPX_MTB{
	meta:
		description = "Trojan:Win64/Zenlod.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba c0 0b 00 00 31 c9 41 b8 00 30 00 00 41 b9 40 00 00 00 e8 ?? ?? ?? ?? 48 89 c6 48 85 c0 0f 84 88 11 00 00 0f 28 05 87 88 1e 00 0f 11 06 0f 28 05 8d 88 1e 00 0f 11 46 10 0f 28 05 92 88 1e 00 0f 11 46 20 0f 28 05 97 88 1e 00 0f 11 46 30 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}