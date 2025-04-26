
rule PWS_Win32_Oirtuk_A{
	meta:
		description = "PWS:Win32/Oirtuk.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 69 6f 20 2d 20 6e 6f 20 6f 72 6b 75 74 20 2d } //1 cio - no orkut -
		$a_01_1 = {4f 69 20 61 6d 6f 72 2e 2e } //1 Oi amor..
		$a_01_2 = {6f 72 6b 75 74 20 2d 20 45 66 65 74 75 61 72 20 6c 6f 67 69 6e 20 2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 orkut - Efetuar login - Microsoft Internet Explorer
		$a_01_3 = {4f 52 4b 55 54 20 41 75 74 6f 20 49 6e 66 65 63 74 } //3 ORKUT Auto Infect
		$a_01_4 = {53 65 6e 68 61 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e } //1 Senha...........
		$a_01_5 = {6f 72 6b 75 74 2e 63 6f 6d 2f 43 6f 6d 70 6f 73 65 2e 61 73 70 78 } //1 orkut.com/Compose.aspx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}