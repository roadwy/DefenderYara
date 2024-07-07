
rule Trojan_Win32_CobaltStrike_MX_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb ff 46 90 01 01 8b 56 90 01 01 8b 86 90 01 04 c1 e9 90 01 01 88 0c 02 ff 46 90 01 01 8b 86 90 01 04 83 e8 90 01 01 31 86 90 01 04 8b 46 90 01 01 83 e8 90 01 01 31 46 90 01 01 8b 4e 90 01 01 8b 86 90 01 04 88 1c 01 8b 46 90 01 01 ff 46 90 01 01 2d 90 01 04 01 86 90 01 04 8b 86 90 01 04 29 46 90 01 01 8b 4e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}