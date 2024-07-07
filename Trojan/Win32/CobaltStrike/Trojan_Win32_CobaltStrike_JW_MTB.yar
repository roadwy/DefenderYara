
rule Trojan_Win32_CobaltStrike_JW_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.JW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 1c 07 83 c7 90 01 01 0f af 5e 90 01 01 8b 46 90 01 01 8b d3 c1 ea 90 01 01 88 14 01 ff 46 90 01 01 8b 4e 90 00 } //1
		$a_03_1 = {03 c1 01 86 90 01 04 b8 90 01 04 8b 0d 90 01 04 2b 86 90 01 04 2b 86 90 01 04 01 81 90 01 04 c7 06 90 01 04 a1 90 01 04 8b 0d 90 01 04 2b 88 90 01 04 49 01 8e 90 01 04 81 ff 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}