
rule Trojan_Win32_Redline_ZMJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 ff 75 90 01 01 c1 e0 04 03 c7 33 45 90 01 01 89 45 90 01 01 8d 45 90 01 01 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}