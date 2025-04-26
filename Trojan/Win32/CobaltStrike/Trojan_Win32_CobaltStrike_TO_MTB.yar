
rule Trojan_Win32_CobaltStrike_TO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.TO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 07 47 84 c0 75 ?? 2b f9 33 f6 8b c6 ?? f7 ff 8a 44 15 ?? 32 84 35 ?? ?? ?? ?? 88 84 35 ?? ?? ?? ?? 0f b6 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}