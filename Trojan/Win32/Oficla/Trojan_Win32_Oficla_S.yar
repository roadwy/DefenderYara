
rule Trojan_Win32_Oficla_S{
	meta:
		description = "Trojan:Win32/Oficla.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c2 01 30 01 83 c1 01 83 fa 10 75 ec 83 c3 10 81 fb 90 01 04 75 d0 90 00 } //1
		$a_01_1 = {eb 0b 83 c3 01 39 5f 18 76 } //1
		$a_01_2 = {69 6e 74 72 6f 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}