
rule TrojanSpy_Win32_Bancos_ABQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.ABQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 6b 61 6d 75 72 75 6d 61 6e 64 72 74 79 } //1 nkamurumandrty
		$a_01_1 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 6c 00 65 00 69 00 61 00 6d 00 65 00 31 00 2e 00 74 00 78 00 74 00 } //1 AppData\leiame1.txt
		$a_01_2 = {61 00 6f 00 20 00 70 00 72 00 6f 00 63 00 75 00 72 00 61 00 72 00 20 00 6f 00 20 00 6e 00 6f 00 6d 00 65 00 20 00 64 00 6f 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 61 00 64 00 6f 00 72 00 2e 00 } //1 ao procurar o nome do computador.
		$a_01_3 = {57 00 49 00 4e 00 20 00 37 00 20 00 4f 00 55 00 52 00 20 00 57 00 49 00 4e 00 56 00 49 00 53 00 54 00 } //1 WIN 7 OUR WINVIST
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}