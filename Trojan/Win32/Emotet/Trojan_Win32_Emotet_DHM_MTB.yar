
rule Trojan_Win32_Emotet_DHM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 5c 24 1c c1 e3 02 0f b6 54 24 1d 89 d1 c1 f9 04 09 d9 88 0f 89 d3 c1 e3 04 0f b6 54 24 1e 89 d1 c1 f9 02 09 d9 88 4f 01 8d 4f 03 c1 e2 06 0a 54 24 1f 88 57 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}