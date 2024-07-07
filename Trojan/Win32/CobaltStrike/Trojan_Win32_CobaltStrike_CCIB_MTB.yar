
rule Trojan_Win32_CobaltStrike_CCIB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d1 83 e1 90 01 01 8a 0c 0e 8b 75 90 01 01 32 0c 16 88 0c 10 42 39 d3 75 e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}