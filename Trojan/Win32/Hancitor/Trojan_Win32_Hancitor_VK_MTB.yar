
rule Trojan_Win32_Hancitor_VK_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 ce 83 e6 03 75 [0-02] 8b 5d 10 66 01 da 66 f7 da 6b d2 03 c1 ca 07 89 55 10 30 10 40 e2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}