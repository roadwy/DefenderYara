
rule Trojan_Win32_Lazy_ALZ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 17 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 fb 80 eb e8 01 f4 89 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}