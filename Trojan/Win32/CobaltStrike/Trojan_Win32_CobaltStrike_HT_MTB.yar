
rule Trojan_Win32_CobaltStrike_HT_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.HT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 8d 0c 3a 83 e0 ?? 8a 80 ?? ?? ?? ?? 32 04 0e 42 88 01 3b 15 ?? ?? ?? ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}