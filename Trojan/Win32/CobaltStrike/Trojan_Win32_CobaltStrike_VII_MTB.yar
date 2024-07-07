
rule Trojan_Win32_CobaltStrike_VII_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.VII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 04 11 83 c2 90 01 01 8b 86 90 01 04 2b 46 90 01 01 2d 90 01 04 01 86 90 01 04 8b 86 90 01 04 01 86 90 01 04 81 fa 90 01 04 7c 90 01 01 90 0a 46 00 2b 46 90 01 01 01 46 90 01 01 8b 46 90 01 01 29 46 90 01 01 8b 8e 90 01 04 8b 86 90 00 } //1
		$a_01_1 = {78 69 61 6f 70 69 6e } //1 xiaopin
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}