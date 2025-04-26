
rule Trojan_Win32_Copak_DO_MTB{
	meta:
		description = "Trojan:Win32/Copak.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 77 fa ca e7 5b 43 31 3e bb 80 23 d9 27 46 81 e8 01 00 00 00 09 c3 29 db 39 ce 75 } //2
		$a_01_1 = {29 c0 5f 81 c0 12 76 98 2e 46 89 db 68 89 2a b2 d6 8b 04 24 83 c4 04 81 eb 60 c4 30 df 81 fe bf 8d 00 01 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}