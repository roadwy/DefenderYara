
rule Trojan_Win32_XBlocker_FVD_MTB{
	meta:
		description = "Trojan:Win32/XBlocker.FVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b fa c1 e7 ?? 0b fa 66 31 38 41 38 99 ?? ?? ?? ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}