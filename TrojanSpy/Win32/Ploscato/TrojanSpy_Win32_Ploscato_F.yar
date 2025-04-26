
rule TrojanSpy_Win32_Ploscato_F{
	meta:
		description = "TrojanSpy:Win32/Ploscato.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2d 73 65 74 64 00 } //1 猭瑥d
		$a_01_1 = {55 73 61 67 65 3a 20 2d 5b 73 74 61 72 74 7c 73 74 6f 70 7c 69 6e 73 74 61 6c 6c 7c 75 6e 69 6e 73 74 61 6c 6c 5d } //1 Usage: -[start|stop|install|uninstall]
		$a_01_2 = {61 6c 65 72 74 2e 25 73 00 } //1
		$a_01_3 = {62 65 61 63 6f 6e 2e 25 73 2e 25 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}