
rule Trojan_Win32_ModiLoader_AML_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 90 01 01 8d be 00 20 01 00 8b 07 09 c0 74 90 01 01 8b 5f 04 8d 84 30 14 4e 01 00 01 f3 50 83 c7 08 ff 96 a0 4e 01 00 95 8a 07 47 08 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}