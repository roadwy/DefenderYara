
rule Trojan_Win32_Mikey_AIV_MTB{
	meta:
		description = "Trojan:Win32/Mikey.AIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 1f 8b 55 e8 8b 5d d4 8a 2c 1a 88 2d 55 8b 26 10 88 0d 56 8b 26 10 30 cd 88 2d 54 8b 26 10 c7 05 ?? ?? ?? ?? 4e 0a 00 00 8b 55 e4 88 2c 1a 81 c3 01 00 00 00 8b 55 f0 39 d3 89 5d c8 75 12 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}