
rule Trojan_Win32_Bunitu_PVN_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c0 33 05 90 01 04 8b c0 90 00 } //1
		$a_02_1 = {8b c0 8b c8 8b d1 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5f 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}