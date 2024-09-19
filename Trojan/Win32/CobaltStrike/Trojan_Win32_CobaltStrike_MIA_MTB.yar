
rule Trojan_Win32_CobaltStrike_MIA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 0f b6 c0 0f b6 44 04 10 30 81 ?? ?? ?? ?? 8d 83 ?? ?? ?? ?? 03 c1 0f b6 c0 0f b6 44 04 10 30 81 ?? ?? ?? ?? 8b 44 24 0c 8d 80 ?? ?? ?? ?? 03 c1 0f b6 c0 0f b6 44 04 10 30 81 ?? ?? ?? ?? 83 c1 06 81 f9 d8 06 00 00 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}