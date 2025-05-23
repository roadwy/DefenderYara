
rule Trojan_Win32_Banker{
	meta:
		description = "Trojan:Win32/Banker,SIGNATURE_TYPE_PEHSTR,18 00 18 00 0a 00 00 "
		
	strings :
		$a_01_0 = {5c 70 69 64 66 65 6e 6f 6e 2e 64 6c 6c } //5 \pidfenon.dll
		$a_01_1 = {5c 70 61 72 75 69 73 64 2e 64 6c 6c } //5 \paruisd.dll
		$a_01_2 = {7b 43 38 41 33 42 39 39 34 2d 45 32 37 41 2d 34 32 66 35 2d 41 30 35 33 2d 43 36 33 37 39 39 45 36 32 31 46 42 7d } //5 {C8A3B994-E27A-42f5-A053-C63799E621FB}
		$a_01_3 = {7b 41 33 38 37 32 38 41 36 2d 36 33 44 39 2d 34 33 65 65 2d 42 46 37 46 2d 31 42 43 45 36 30 38 36 31 39 31 46 7d } //3 {A38728A6-63D9-43ee-BF7F-1BCE6086191F}
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 52 53 6f 66 74 } //2 Software\MRSoft
		$a_01_5 = {52 49 54 4c 41 42 2e 31 } //2 RITLAB.1
		$a_01_6 = {3e 3e 20 4e 55 4c } //1 >> NUL
		$a_01_7 = {2f 63 20 64 65 6c 20 } //1 /c del 
		$a_01_8 = {5c 63 6f 6e 66 2e 64 61 74 } //1 \conf.dat
		$a_01_9 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=24
 
}
rule Trojan_Win32_Banker_2{
	meta:
		description = "Trojan:Win32/Banker,SIGNATURE_TYPE_PEHSTR,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 41 72 63 68 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6d 73 67 73 2e 65 78 65 } //10 C:\Archivos de programa\Messenger\msmsgs.exe
		$a_01_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 2e 00 70 00 72 00 65 00 } //10 \system32\drivers\etc\hosts.pre
		$a_01_2 = {62 00 61 00 6e 00 61 00 6d 00 65 00 78 00 2e 00 63 00 6f 00 6d 00 } //1 banamex.com
		$a_01_3 = {62 00 61 00 6e 00 61 00 6d 00 65 00 78 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 78 00 } //1 banamex.com.mx
		$a_01_4 = {62 00 6f 00 76 00 65 00 64 00 61 00 2e 00 62 00 61 00 6e 00 61 00 6d 00 65 00 78 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 78 00 } //1 boveda.banamex.com.mx
		$a_01_5 = {62 00 61 00 6e 00 63 00 61 00 6e 00 65 00 74 00 65 00 6d 00 70 00 72 00 65 00 73 00 61 00 72 00 69 00 61 00 6c 00 2e 00 62 00 61 00 6e 00 61 00 6d 00 65 00 78 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 78 00 } //1 bancanetempresarial.banamex.com.mx
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=24
 
}
rule Trojan_Win32_Banker_3{
	meta:
		description = "Trojan:Win32/Banker,SIGNATURE_TYPE_PEHSTR,ffffffba 00 ffffffb8 00 18 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //100 C:\Arquivos de programas\Microsoft Visual Studio\VB98\VB6.OLB
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 42 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 20 00 43 00 41 00 49 00 58 00 41 00 20 00 2d 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 } //10 Internet Banking CAIXA - Microsoft Internet Explorer
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 32 00 2e 00 62 00 61 00 6e 00 63 00 6f 00 62 00 72 00 61 00 73 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 } //10 https://www2.bancobrasil.com.br/
		$a_01_4 = {69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 63 00 61 00 69 00 78 00 61 00 2e 00 63 00 61 00 69 00 78 00 61 00 2e 00 67 00 6f 00 76 00 2e 00 62 00 72 00 } //10 internetcaixa.caixa.gov.br
		$a_01_5 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 62 00 61 00 6e 00 6b 00 6c 00 69 00 6e 00 65 00 2e 00 69 00 74 00 61 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 } //10 https://bankline.itau.com.br/
		$a_01_6 = {42 00 61 00 6e 00 63 00 6f 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 3a 00 20 00 42 00 61 00 6e 00 63 00 6f 00 20 00 64 00 6f 00 20 00 42 00 72 00 61 00 73 00 69 00 6c 00 } //10 Banco.....................: Banco do Brasil
		$a_01_7 = {43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 6d 00 75 00 6c 00 74 00 69 00 70 00 61 00 72 00 74 00 2f 00 6d 00 69 00 78 00 65 00 64 00 3b 00 20 00 62 00 6f 00 75 00 6e 00 64 00 61 00 72 00 79 00 3d 00 4e 00 65 00 78 00 74 00 4d 00 69 00 6d 00 65 00 50 00 61 00 72 00 74 00 } //10 Content-Type: multipart/mixed; boundary=NextMimePart
		$a_01_8 = {50 72 6f 6a 65 74 6f 46 75 63 61 70 69 } //1 ProjetoFucapi
		$a_01_9 = {73 76 68 6f 6f 74 73 73 } //1 svhootss
		$a_01_10 = {47 00 4f 00 44 00 20 00 44 00 41 00 4d 00 4e 00 49 00 54 00 2c 00 20 00 74 00 68 00 65 00 20 00 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 64 00 6f 00 65 00 73 00 6e 00 27 00 74 00 20 00 77 00 6f 00 72 00 6b 00 } //1 GOD DAMNIT, the internet doesn't work
		$a_01_11 = {49 00 66 00 20 00 77 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 3d 00 3d 00 20 00 32 00 35 00 37 00 20 00 74 00 68 00 65 00 6e 00 20 00 65 00 76 00 65 00 72 00 79 00 74 00 68 00 69 00 6e 00 67 00 20 00 69 00 73 00 20 00 6b 00 65 00 77 00 6c 00 } //1 If wVersion == 257 then everything is kewl
		$a_01_12 = {40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00 } //1 @yahoo.com
		$a_01_13 = {4e 00 61 00 63 00 69 00 6f 00 6e 00 61 00 6c 00 21 00 } //1 Nacional!
		$a_01_14 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 2a 00 2e 00 67 00 70 00 63 00 } //1 C:\WINDOWS\Downloaded Program Files\*.gpc
		$a_01_15 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 2a 00 2e 00 67 00 6d 00 64 00 } //1 C:\WINDOWS\Downloaded Program Files\*.gmd
		$a_01_16 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 2a 00 2e 00 64 00 6c 00 6c 00 } //1 C:\WINDOWS\Downloaded Program Files\*.dll
		$a_01_17 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 2a 00 2e 00 69 00 6e 00 66 00 } //1 C:\WINDOWS\Downloaded Program Files\*.inf
		$a_01_18 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 74 00 61 00 73 00 6b 00 73 00 5c 00 73 00 74 00 61 00 72 00 74 00 2e 00 6a 00 6f 00 62 00 } //1 C:\WINDOWS\tasks\start.job
		$a_01_19 = {6b 00 33 00 34 00 6c 00 75 00 70 00 61 00 74 00 6f 00 70 00 40 00 6b 00 31 00 72 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 k34lupatop@k1r.com.br
		$a_01_20 = {4e 00 6f 00 72 00 74 00 6f 00 6e 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 } //1 Norton AntiVirus
		$a_01_21 = {4c 00 6f 00 63 00 61 00 6c 00 20 00 64 00 6f 00 20 00 43 00 65 00 72 00 74 00 69 00 66 00 69 00 63 00 61 00 64 00 6f 00 4b 00 45 00 59 00 2e 00 3a 00 } //1 Local do CertificadoKEY.:
		$a_01_22 = {4e 00 6f 00 72 00 74 00 6f 00 6e 00 20 00 52 00 65 00 63 00 65 00 62 00 65 00 75 00 20 00 31 00 20 00 2d 00 20 00 53 00 4d 00 54 00 50 00 } //1 Norton Recebeu 1 - SMTP
		$a_01_23 = {73 00 76 00 68 00 6f 00 6f 00 74 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 svhootss.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1) >=184
 
}