
rule Trojan_Win32_Calelk_A{
	meta:
		description = "Trojan:Win32/Calelk.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 fa 10 75 02 33 d2 ac 32 82 ?? ?? ?? ?? aa 42 49 75 ed } //1
		$a_01_1 = {6a 09 6a 01 6a 6c 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}