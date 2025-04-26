
rule Trojan_Win32_Redline_SLA_MTB{
	meta:
		description = "Trojan:Win32/Redline.SLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f b6 d1 d0 c9 f6 de 81 fd ?? ?? ?? ?? 32 d9 89 04 0c 8d ad ?? ?? ?? ?? 8b 54 25 ?? 66 ?? ?? 33 d3 f7 c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}