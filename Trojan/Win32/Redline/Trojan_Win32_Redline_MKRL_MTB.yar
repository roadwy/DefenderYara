
rule Trojan_Win32_Redline_MKRL_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 d3 e8 8b d5 8d 4c 24 ?? 89 44 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 33 4c 24 ?? 89 35 ?? ?? ?? ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}