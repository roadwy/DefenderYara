
rule Trojan_Win32_Redline_GDJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 59 8a 80 ?? ?? ?? ?? 32 c3 88 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}