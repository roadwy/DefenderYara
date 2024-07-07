
rule TrojanSpy_Win32_Bancos_ZO{
	meta:
		description = "TrojanSpy:Win32/Bancos.ZO,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 20 42 61 6e 6b 69 6e 67 20 43 61 69 78 61 20 2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 } //3 Internet Banking Caixa - Microsoft Internet Explorer 
		$a_01_1 = {45 64 69 74 73 65 6e 68 61 63 61 72 74 61 6f 4b 65 79 50 72 65 73 73 } //3 EditsenhacartaoKeyPress
		$a_01_2 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 20 43 2e 40 2e 31 2e 58 2e 40 20 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d } //5 ================= C.@.1.X.@ ==================
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*5) >=11
 
}