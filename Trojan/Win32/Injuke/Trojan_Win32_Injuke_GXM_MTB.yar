
rule Trojan_Win32_Injuke_GXM_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {54 83 fe 1a 2b 43 fe 09 0d ?? ?? ?? ?? 1e fe 0b 0a 09 fe 0b 11 1c ff 4b 56 73 ?? 09 08 08 11 } //10
		$a_80_1 = {48 65 72 6f 44 75 6e } //HeroDun  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}