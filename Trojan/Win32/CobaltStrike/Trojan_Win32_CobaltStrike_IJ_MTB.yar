
rule Trojan_Win32_CobaltStrike_IJ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.IJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 0e 83 e0 ?? 0f b6 80 ?? ?? ?? ?? 32 42 ?? 88 41 ?? 8d 04 0b 83 e0 ?? 8d 49 ?? 0f b6 80 ?? ?? ?? ?? 32 02 88 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}