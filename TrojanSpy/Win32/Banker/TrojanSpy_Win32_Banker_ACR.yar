
rule TrojanSpy_Win32_Banker_ACR{
	meta:
		description = "TrojanSpy:Win32/Banker.ACR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 40 0c 20 4e 00 00 8d 4d } //1
		$a_01_1 = {ba 90 80 84 2d 8b 45 } //1
		$a_01_2 = {c7 45 fc 91 be 32 b9 8d 45 } //1
		$a_03_3 = {c7 43 2c 20 1c 00 00 a1 90 09 05 00 e8 90 00 } //1
		$a_01_4 = {c7 40 0c 98 3a 00 00 8d 4d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}