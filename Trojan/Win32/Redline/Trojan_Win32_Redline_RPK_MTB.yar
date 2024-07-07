
rule Trojan_Win32_Redline_RPK_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 0c 8b 45 e8 03 f0 33 d2 f7 75 14 8b 45 08 8a 04 02 8a c8 02 c0 02 c8 c0 e1 05 30 0e ff 45 e8 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}