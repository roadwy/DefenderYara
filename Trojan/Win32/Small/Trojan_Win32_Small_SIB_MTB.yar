
rule Trojan_Win32_Small_SIB_MTB{
	meta:
		description = "Trojan:Win32/Small.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 2b d6 8b fb 8a 0c 02 88 08 40 83 ef 01 75 90 01 01 33 c9 8b c1 83 e0 90 01 01 8a 80 90 01 04 30 04 31 41 3b cb 72 90 01 01 8b ce e8 90 01 04 64 8b 0d 30 00 00 00 89 41 08 8b 49 0c 8b 49 14 89 41 10 8b 48 3c 8b 4c 01 28 03 c8 ff d1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}