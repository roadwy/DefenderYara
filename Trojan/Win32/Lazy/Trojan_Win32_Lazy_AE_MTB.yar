
rule Trojan_Win32_Lazy_AE_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 83 f8 0a 0f 9c c3 20 c3 89 d0 20 c8 08 d8 30 d1 20 d1 89 ca 20 c2 30 c1 08 d1 89 c2 30 ca 80 f1 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}