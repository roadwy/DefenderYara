
rule PWS_Win32_Blankit_A{
	meta:
		description = "PWS:Win32/Blankit.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 00 41 00 4e 00 43 00 4f 00 42 00 52 00 41 00 44 00 45 00 53 00 43 00 4f 00 7c 00 42 00 41 00 4e 00 43 00 4f 00 49 00 54 00 41 00 55 00 7c 00 33 00 30 00 48 00 4f 00 52 00 41 00 53 00 7c 00 } //2 BANCOBRADESCO|BANCOITAU|30HORAS|
		$a_01_1 = {5c 00 44 00 41 00 44 00 4f 00 53 00 2e 00 74 00 78 00 74 00 } //2 \DADOS.txt
		$a_01_2 = {6f 20 64 65 20 73 65 6e 68 61 20 65 66 65 74 69 76 61 63 61 6f 2e } //1 o de senha efetivacao.
		$a_01_3 = {5b 4f 6b 5d 20 53 6f 6c 69 63 69 74 61 } //1 [Ok] Solicita
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}