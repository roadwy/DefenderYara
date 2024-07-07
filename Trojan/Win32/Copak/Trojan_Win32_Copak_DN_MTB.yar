
rule Trojan_Win32_Copak_DN_MTB{
	meta:
		description = "Trojan:Win32/Copak.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 db 43 31 01 89 de 01 f6 41 83 ec 04 89 34 24 8b 1c 24 83 c4 04 39 d1 75 } //2
		$a_01_1 = {29 d3 81 c2 1d 39 57 7c 8b 04 24 83 c4 04 81 c2 01 00 00 00 21 db 4a 46 89 db 81 fe b5 26 00 01 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}