
rule Trojan_Win32_CobaltStrike_UM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.UM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 90 01 01 88 14 01 ff 46 90 01 01 8b 4e 90 01 01 8b 86 90 01 04 88 1c 01 ff 46 90 01 01 8b 86 90 01 04 83 e8 90 01 01 31 86 90 01 04 8b 46 90 00 } //1
		$a_03_1 = {31 04 11 b8 90 01 04 2b 86 90 01 04 83 c2 90 01 01 2b 46 90 01 01 01 46 90 01 01 8b 86 90 01 04 01 46 90 01 01 b8 90 01 04 2b 46 90 01 01 01 46 90 01 01 81 fa 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}