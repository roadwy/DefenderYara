
rule Trojan_Win32_Redline_DCC_MTB{
	meta:
		description = "Trojan:Win32/Redline.DCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 0c 8b 45 e4 01 45 0c 8b 45 0c 33 45 f8 33 c8 89 4d ec 8b 45 ec 29 45 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}