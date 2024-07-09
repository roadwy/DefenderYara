
rule Trojan_Win32_Injuke_CCHS_MTB{
	meta:
		description = "Trojan:Win32/Injuke.CCHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 06 01 d1 b9 ?? ?? ?? ?? 81 c6 04 00 00 00 39 fe 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}