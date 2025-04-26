
rule Trojan_Win32_Redline_MWE_MTB{
	meta:
		description = "Trojan:Win32/Redline.MWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 8d 4c 24 40 8a 44 04 58 30 87 ?? ?? ?? ?? e8 ?? ?? ?? ?? 47 81 ff ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}