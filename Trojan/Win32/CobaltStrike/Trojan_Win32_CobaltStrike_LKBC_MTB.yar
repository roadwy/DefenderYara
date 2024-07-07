
rule Trojan_Win32_CobaltStrike_LKBC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LKBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 68 90 01 02 03 00 8b 85 90 01 04 05 90 01 02 03 00 50 68 90 01 02 04 00 68 00 90 01 03 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}