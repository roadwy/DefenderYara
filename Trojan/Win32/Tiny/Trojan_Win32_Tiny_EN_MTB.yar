
rule Trojan_Win32_Tiny_EN_MTB{
	meta:
		description = "Trojan:Win32/Tiny.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e2 02 8b 5d 00 8b 5b 08 8b 1b 89 d9 8b 1b 8b 45 08 c1 e0 02 01 c3 8b 1b 85 db 81 fb 01 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}