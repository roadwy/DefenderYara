
rule Trojan_Win32_CobaltStrike_PT_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cd c1 ea ?? 6b c2 ?? 2b c8 03 ce 8a 44 0c ?? 32 86 ?? ?? ?? ?? 46 88 47 ?? 81 fe ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}