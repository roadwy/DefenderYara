
rule Trojan_Win32_Farfli_DAP_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 51 c7 45 e0 43 72 65 61 c7 45 e4 74 65 45 76 c7 45 e8 65 6e 74 41 88 5d ec ff d7 } //2
		$a_01_1 = {8d 45 e0 50 51 c7 45 e0 43 72 65 61 c7 45 e4 74 65 45 76 c7 45 e8 65 6e 74 41 88 5d ec ff d7 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}