
rule Trojan_Win32_Zenpak_AF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 ff 89 55 f8 88 45 f7 8a 45 f7 0f b6 c8 8b 55 f8 31 ca 88 d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}