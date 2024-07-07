
rule Trojan_Win32_CobaltStrike_AE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 0f b7 01 33 d2 66 2b 90 01 05 33 d2 66 f7 90 01 05 33 d2 88 06 33 d2 46 33 d2 43 33 d2 83 c1 02 33 d7 3b da 7c 90 01 02 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}