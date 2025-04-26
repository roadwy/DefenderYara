
rule TrojanSpy_Win32_Delf_BY{
	meta:
		description = "TrojanSpy:Win32/Delf.BY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 70 74 75 72 6f 75 20 53 65 6e 68 61 5f 48 6f 74 4d 61 69 6c 20 2d 3e } //3 Capturou Senha_HotMail ->
		$a_01_1 = {43 61 70 74 75 72 6f 75 20 55 73 75 61 72 69 6f 5f 47 6d 61 69 6c 20 2d 3e } //3 Capturou Usuario_Gmail ->
		$a_01_2 = {6d 61 69 6c 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //1 mail.terra.com.br
		$a_01_3 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 5c 57 69 6e 64 6f 77 4d 65 74 72 69 63 73 5c 4d 69 6e 41 6e 69 6d 61 74 65 } //1 Control Panel\Desktop\WindowMetrics\MinAnimate
		$a_01_4 = {5b 5b 5b 5b 5b 46 49 4d 20 53 45 20 4d 41 54 41 52 5d 5d 5d 5d 5d } //2 [[[[[FIM SE MATAR]]]]]
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=6
 
}