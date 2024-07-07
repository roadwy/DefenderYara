
rule Trojan_Win32_Lazy_A_MTB{
	meta:
		description = "Trojan:Win32/Lazy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 ec 04 c7 04 24 e4 dd ee 13 83 c4 04 83 c6 01 8a 46 ff 68 c8 b2 c8 fb 83 c4 04 c7 44 24 fc f5 5f c2 39 32 02 c7 44 24 fc 85 87 63 9a 83 c7 01 88 47 ff 89 c0 68 fe f9 1a ca 83 c4 04 83 c2 02 4a 90 c7 44 24 fc 0f 8c 2a 15 83 e9 02 41 57 83 c4 04 90 85 c9 75 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}