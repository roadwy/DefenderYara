
rule Trojan_Win32_Carmapic_A{
	meta:
		description = "Trojan:Win32/Carmapic.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 37 d1 e9 d2 f6 3f 7c 2c 96 a2 eb 96 c8 4e 3b 29 f8 cc 15 ad c7 18 41 56 d6 d3 79 2b 26 97 66 ce 84 30 b7 85 d0 46 16 9b e8 f5 29 73 ac e9 db 53 af 15 80 c3 4c 40 8e 49 cf fc bf cf 46 e0 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}