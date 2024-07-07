
rule Trojan_Win32_CobaltStrike_ME_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 f7 f7 80 c2 35 30 54 0d d4 41 83 f9 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}