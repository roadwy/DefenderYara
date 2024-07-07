
rule Trojan_Win32_CobaltStrike_ZF_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 04 31 83 c6 90 01 01 a1 90 01 04 01 05 90 01 04 a1 90 01 04 8b 0d 90 01 04 05 90 01 04 8b 15 90 01 04 03 c1 a3 90 01 04 81 c1 90 01 04 8b 42 90 01 01 03 c1 8b 0d 90 01 04 33 0d 90 01 04 a3 90 01 04 a1 90 01 04 05 90 01 04 03 c1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}