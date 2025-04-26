
rule Trojan_Win32_Wefawix_A{
	meta:
		description = "Trojan:Win32/Wefawix.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ba 33 01 00 00 89 d1 83 ec 0c 99 f7 f9 56 8b 1c 95 } //1
		$a_01_1 = {83 fb 46 5a 74 12 eb df 83 ec 0c 68 f4 01 00 00 e8 } //1
		$a_01_2 = {ba ff 00 00 00 89 d1 83 c4 0c 99 f7 f9 0f be d2 68 00 20 03 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}