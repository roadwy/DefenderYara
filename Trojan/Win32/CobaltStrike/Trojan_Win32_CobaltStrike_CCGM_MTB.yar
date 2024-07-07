
rule Trojan_Win32_CobaltStrike_CCGM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CCGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 8b 4d 08 f7 35 90 01 04 6b d2 0c 39 8a 90 01 04 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}