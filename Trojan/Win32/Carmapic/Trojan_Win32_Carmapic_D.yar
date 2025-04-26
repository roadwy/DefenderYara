
rule Trojan_Win32_Carmapic_D{
	meta:
		description = "Trojan:Win32/Carmapic.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 37 db a6 6d ec c7 37 43 a0 d0 a1 d2 e4 44 91 4a 6a 72 dc 9a d3 ce 38 1d 71 e7 da 20 16 9e 64 69 b3 23 a6 12 bf 51 2a e5 85 8e 83 34 51 19 c7 2c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}