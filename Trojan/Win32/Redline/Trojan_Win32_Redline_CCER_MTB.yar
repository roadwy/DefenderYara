
rule Trojan_Win32_Redline_CCER_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 0f be 06 33 c1 69 c0 ?? ?? ?? ?? 33 f8 8b 6c 24 ?? 8b c7 c1 e8 ?? 33 c7 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 0f 33 c8 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}