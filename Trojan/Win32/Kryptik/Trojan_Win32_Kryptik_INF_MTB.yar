
rule Trojan_Win32_Kryptik_INF_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.INF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 d9 d3 ef 8b 4c 24 3c 8b 0c 8d 00 80 42 00 31 d1 8b 94 24 9c 00 00 00 89 bc 24 bc 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}