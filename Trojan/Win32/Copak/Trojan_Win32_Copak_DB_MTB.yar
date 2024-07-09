
rule Trojan_Win32_Copak_DB_MTB{
	meta:
		description = "Trojan:Win32/Copak.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 f6 21 f7 e8 [0-04] 01 fe 31 19 81 c1 01 00 00 00 39 c1 75 e4 } //2
		$a_01_1 = {89 c0 8b 0c 24 83 c4 04 09 c0 09 c3 01 d8 42 01 db 81 fa 4e 80 00 01 75 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}