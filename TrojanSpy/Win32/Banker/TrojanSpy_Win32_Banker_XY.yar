
rule TrojanSpy_Win32_Banker_XY{
	meta:
		description = "TrojanSpy:Win32/Banker.XY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {70 72 61 71 75 65 6d 3d 90 02 20 40 90 03 0b 09 68 6f 74 6d 61 69 6c 2e 63 6f 6d 67 6d 61 69 6c 2e 63 6f 6d 90 00 } //1
		$a_00_1 = {53 65 6e 68 61 20 69 6e 74 65 72 6e 65 74 } //1 Senha internet
		$a_00_2 = {74 69 74 75 6c 6f 3d 3a 3a } //1 titulo=::
		$a_00_3 = {6f 20 74 65 63 6c 61 64 6f 20 76 69 72 74 75 61 6c } //1 o teclado virtual
		$a_00_4 = {69 6e 6a 65 74 65 6c 2e 63 6f 6d 2e 62 72 } //1 injetel.com.br
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}