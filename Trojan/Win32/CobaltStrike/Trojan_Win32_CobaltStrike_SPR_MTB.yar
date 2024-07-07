
rule Trojan_Win32_CobaltStrike_SPR_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 33 c2 33 c1 81 3d 90 01 04 a3 01 00 00 89 45 fc 75 20 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}