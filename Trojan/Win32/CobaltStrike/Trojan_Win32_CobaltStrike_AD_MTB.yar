
rule Trojan_Win32_CobaltStrike_AD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 0f b7 01 33 d2 66 2b 90 01 05 33 d2 66 f7 90 01 05 33 d2 88 06 33 d2 46 33 d2 43 33 d2 83 c1 02 33 d2 3b df 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}