
rule Trojan_Win32_Copak_DM_MTB{
	meta:
		description = "Trojan:Win32/Copak.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 c7 81 c7 67 61 97 c3 e8 [0-04] 09 c7 b8 74 e0 d1 53 31 16 09 f8 81 c6 01 00 00 00 50 5f 39 de 75 } //2
		$a_01_1 = {5a 09 db 81 c7 d3 4e 1e 83 40 01 db 47 47 81 f8 fe e6 00 01 75 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}