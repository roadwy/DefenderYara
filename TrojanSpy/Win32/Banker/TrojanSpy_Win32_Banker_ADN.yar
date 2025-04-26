
rule TrojanSpy_Win32_Banker_ADN{
	meta:
		description = "TrojanSpy:Win32/Banker.ADN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ?? ?? ?? ?? 83 f8 07 75 1c 6a 01 e8 } //1
		$a_00_1 = {50 72 65 65 6e 63 68 61 20 63 6f 72 72 65 74 61 6d 65 6e 74 65 20 6f 73 20 63 61 6d 70 6f 73 20 73 6f 6c 69 63 69 74 61 64 6f 73 } //1 Preencha corretamente os campos solicitados
		$a_00_2 = {2e 70 68 70 } //1 .php
		$a_02_3 = {65 78 65 63 [0-10] 73 65 72 69 65 } //1
		$a_01_4 = {40 68 6f 74 6d 61 69 6c 2e 63 6f 6d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}