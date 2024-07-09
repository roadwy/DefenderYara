
rule Trojan_Win32_CobaltStrike_CCGM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CCGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 8b 4d 08 f7 35 ?? ?? ?? ?? 6b d2 0c 39 8a ?? ?? ?? ?? 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}