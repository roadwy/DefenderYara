
rule Trojan_Win32_Rhadamanthys_ARD_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c7 89 c1 c1 ef 18 c1 e9 10 0f b6 c9 0f b6 3c 3a c1 e7 18 0f b6 0c 0a c1 e1 10 09 f9 0f b6 fc 0f b6 c0 0f b6 34 3a c1 e6 08 09 ce 0f b6 3c 02 09 f7 0f ac f9 13 0f ac fe 09 33 7d f0 31 cf 31 f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}