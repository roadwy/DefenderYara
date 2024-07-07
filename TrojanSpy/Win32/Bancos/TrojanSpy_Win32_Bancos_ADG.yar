
rule TrojanSpy_Win32_Bancos_ADG{
	meta:
		description = "TrojanSpy:Win32/Bancos.ADG,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //1 @hotmail.com
		$a_01_1 = {2f 6e 6f 74 65 5f 6d 6f 64 65 2e 70 68 70 } //1 /note_mode.php
		$a_01_2 = {42 61 6e 63 6f 20 53 61 6e 74 61 6e 64 65 72 20 2f 20 52 65 61 6c } //1 Banco Santander / Real
		$a_01_3 = {41 20 4f 4e 2d 4c 49 4e 45 20 46 4f 49 20 42 4c 4f 51 55 45 41 44 4f 20 44 45 56 49 44 4f 20 41 20 33 20 54 45 4e 54 41 54 49 56 41 53 20 49 4e 56 } //1 A ON-LINE FOI BLOQUEADO DEVIDO A 3 TENTATIVAS INV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}