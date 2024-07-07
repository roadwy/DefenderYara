
rule Trojan_Win32_Delf_CJ{
	meta:
		description = "Trojan:Win32/Delf.CJ,SIGNATURE_TYPE_PEHSTR,6e 00 6b 00 11 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //20 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {54 43 75 73 74 6f 6d 4d 65 6d 6f 72 79 53 74 72 65 61 6d } //20 TCustomMemoryStream
		$a_01_2 = {53 65 74 43 61 70 74 75 72 65 } //20 SetCapture
		$a_01_3 = {67 65 74 73 65 72 76 62 79 6e 61 6d 65 } //20 getservbyname
		$a_01_4 = {69 6f 63 74 6c 73 6f 63 6b 65 74 } //20 ioctlsocket
		$a_01_5 = {49 6e 76 65 72 74 65 72 20 42 6f 74 } //1 Inverter Bot
		$a_01_6 = {46 65 63 68 61 72 20 4a 61 6e 65 6c 61 20 64 6f 20 4d 53 4e } //1 Fechar Janela do MSN
		$a_01_7 = {46 6f 72 6d 61 74 61 20 57 69 6e 64 6f 77 73 } //1 Formata Windows
		$a_01_8 = {44 65 73 61 62 69 6c 69 74 61 72 20 42 61 72 72 61 20 64 65 20 54 61 72 65 66 61 73 } //1 Desabilitar Barra de Tarefas
		$a_01_9 = {43 68 61 6d 61 20 57 4f 52 4d } //1 Chama WORM
		$a_01_10 = {43 68 61 6d 61 20 49 6d 61 67 65 6d 20 64 6f 20 46 49 52 45 48 41 43 4b 45 52 } //1 Chama Imagem do FIREHACKER
		$a_01_11 = {43 68 61 6d 61 20 73 6f 6d 20 64 65 20 45 52 52 4f 20 6e 6f 20 50 43 20 64 61 20 76 69 74 69 6d 61 } //1 Chama som de ERRO no PC da vitima
		$a_01_12 = {4f 70 65 6e 20 43 44 2f 44 56 44 20 52 4f 4d } //1 Open CD/DVD ROM
		$a_01_13 = {43 68 61 6e 67 65 20 50 61 70 65 72 20 6f 66 20 57 61 6c 6c } //1 Change Paper of Wall
		$a_01_14 = {50 6f 77 65 72 20 4f 46 46 20 4d 6f 6e 69 74 6f 72 20 28 57 49 4e 39 35 29 } //1 Power OFF Monitor (WIN95)
		$a_01_15 = {43 61 70 74 75 72 61 72 20 49 6d 61 67 65 6d 20 64 61 20 57 65 62 43 61 6d } //1 Capturar Imagem da WebCam
		$a_01_16 = {45 6e 76 69 61 72 20 4d 53 47 2e } //1 Enviar MSG.
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=107
 
}
rule Trojan_Win32_Delf_CJ_2{
	meta:
		description = "Trojan:Win32/Delf.CJ,SIGNATURE_TYPE_PEHSTR,ffffffe2 00 ffffffe0 00 14 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //20 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {54 43 75 73 74 6f 6d 4d 65 6d 6f 72 79 53 74 72 65 61 6d } //20 TCustomMemoryStream
		$a_01_2 = {53 65 74 43 61 70 74 75 72 65 } //20 SetCapture
		$a_01_3 = {67 65 74 73 65 72 76 62 79 6e 61 6d 65 } //20 getservbyname
		$a_01_4 = {69 6f 63 74 6c 73 6f 63 6b 65 74 } //20 ioctlsocket
		$a_01_5 = {43 3a 5c 73 65 6e 68 61 73 2e 74 78 74 } //20 C:\senhas.txt
		$a_01_6 = {43 3a 5c 74 63 73 79 73 74 65 6d 67 65 6e 65 72 61 74 69 6f 6e 2e 74 78 74 } //20 C:\tcsystemgeneration.txt
		$a_01_7 = {53 65 72 76 65 72 53 6f 63 6b 65 74 31 } //20 ServerSocket1
		$a_01_8 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //20 Shell_TrayWnd
		$a_01_9 = {43 3a 5c 77 65 62 63 61 6d 2e 62 6d 70 } //20 C:\webcam.bmp
		$a_01_10 = {53 79 73 74 65 6d 20 54 43 20 67 65 6e 65 72 61 74 69 6f 20 73 75 63 65 66 61 75 6c } //1 System TC generatio sucefaul
		$a_01_11 = {47 45 4e 45 52 41 54 49 4f 4e 45 53 3a 20 } //1 GENERATIONES: 
		$a_01_12 = {43 4f 44 45 47 45 4e 45 52 41 44 3a 20 } //1 CODEGENERAD: 
		$a_01_13 = {53 65 74 20 43 64 41 75 64 69 6f 20 44 6f 6f 72 20 4f 70 65 6e } //1 Set CdAudio Door Open
		$a_01_14 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 41 72 65 6e 69 74 6f 2e 62 6d 70 } //1 C:\windows\Arenito.bmp
		$a_01_15 = {57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 } //1 Windows Live Messenger
		$a_01_16 = {43 6f 6d 6d 61 6e 64 2e 63 6f 6d 20 2f 63 20 44 65 6c 20 63 3a 5c } //1 Command.com /c Del c:\
		$a_01_17 = {5b 4e 75 6d 20 4c 6f 63 6b 5d } //1 [Num Lock]
		$a_01_18 = {6b 65 79 6c 6f 67 67 65 72 20 2d 20 6c 6f 67 73 } //1 keylogger - logs
		$a_01_19 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6f 00 72 00 63 00 75 00 6c 00 74 00 2e 00 30 00 6c 00 78 00 2e 00 6e 00 65 00 74 00 2f 00 74 00 63 00 67 00 65 00 6e 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 68 00 74 00 6d 00 } //20 http://orcult.0lx.net/tcgeneration.htm
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20+(#a_01_8  & 1)*20+(#a_01_9  & 1)*20+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*20) >=224
 
}