
rule Trojan_Win32_Farfli_AFF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0b 89 c2 83 c3 01 c1 ea 04 31 c8 c0 e9 04 83 e0 0f 33 14 85 e0 a6 44 00 89 d0 31 ca 83 e2 0f c1 e8 04 33 04 95 e0 a6 44 00 39 de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}