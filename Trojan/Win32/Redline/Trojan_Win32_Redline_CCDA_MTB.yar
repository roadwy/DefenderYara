
rule Trojan_Win32_Redline_CCDA_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 33 de ?? c0 33 ?? 8b f6 ?? ?? ?? ?? 8b c3 f6 2f 47 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}