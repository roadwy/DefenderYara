
rule Trojan_Win32_CobaltStrike_QL_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.QL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f8 01 15 90 01 04 c1 c0 90 01 01 e8 90 01 04 03 0d 90 01 04 41 e8 90 01 04 87 f7 01 05 90 01 04 81 f6 90 01 04 e8 90 01 04 01 05 90 01 04 e8 90 01 04 81 25 90 01 08 4f 81 f7 90 01 04 89 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}