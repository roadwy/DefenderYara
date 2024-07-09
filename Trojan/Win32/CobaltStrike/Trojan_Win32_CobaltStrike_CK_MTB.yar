
rule Trojan_Win32_CobaltStrike_CK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 d8 7d 17 8b 75 ?? 89 c1 83 e1 ?? 8a 0c 0e 8b 75 08 32 0c 06 88 0c 02 40 eb e5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}