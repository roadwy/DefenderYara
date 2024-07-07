
rule Trojan_Win32_vboox_RDA_MTB{
	meta:
		description = "Trojan:Win32/vboox.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 ee 9b 00 00 00 01 1f 81 f1 15 00 00 00 89 ef 81 f1 8f 00 00 00 09 ce 81 c9 41 00 00 00 81 c9 1d 00 00 00 81 c7 94 00 00 00 81 f1 69 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}