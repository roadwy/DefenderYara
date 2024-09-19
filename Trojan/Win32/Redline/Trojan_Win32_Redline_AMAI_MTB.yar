
rule Trojan_Win32_Redline_AMAI_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 86 0f b6 04 07 30 04 11 8b 4c 24 ?? 83 f9 0f 76 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}