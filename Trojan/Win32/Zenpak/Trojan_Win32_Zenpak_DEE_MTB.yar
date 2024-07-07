
rule Trojan_Win32_Zenpak_DEE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d1 8b fa 04 05 69 ff 67 48 00 00 02 c0 2a 05 90 01 04 01 3d 90 01 04 02 05 90 01 04 3a c3 88 44 24 12 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}