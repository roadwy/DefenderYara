
rule Trojan_Win32_CobaltStrike_XZQ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.XZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c1 01 46 90 01 01 8b 46 90 01 01 8b 8e 90 01 04 8b d3 c1 ea 90 01 01 88 14 01 ff 46 90 01 01 8b 46 90 01 01 29 86 90 01 04 b8 90 01 04 2b 86 90 0a 36 00 83 c7 90 01 01 0f af 5e 90 01 01 8b 86 90 00 } //1
		$a_03_1 = {88 1c 0a ff 40 90 01 01 8b 48 90 01 01 49 01 88 90 01 04 b9 90 01 04 2b 88 90 01 04 2b 48 90 01 01 01 48 90 01 01 8b 88 90 01 04 33 88 90 01 04 31 48 90 01 01 8b 88 90 01 04 81 c1 90 01 04 31 48 90 01 01 81 fe 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}