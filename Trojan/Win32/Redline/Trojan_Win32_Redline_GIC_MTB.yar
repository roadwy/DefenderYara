
rule Trojan_Win32_Redline_GIC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 8b c6 83 e0 03 8a 80 90 01 04 32 c3 02 c3 88 04 0e e8 90 01 04 51 8b c8 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}