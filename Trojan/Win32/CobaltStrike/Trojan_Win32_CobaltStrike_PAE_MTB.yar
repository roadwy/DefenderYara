
rule Trojan_Win32_CobaltStrike_PAE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 e8 03 e8 03 e8 8b 44 24 90 01 01 8a 0c 28 8b 44 24 90 01 01 8a 18 32 d9 8b 4c 24 90 01 01 88 18 8b 44 24 90 01 01 40 3b c1 89 44 24 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}