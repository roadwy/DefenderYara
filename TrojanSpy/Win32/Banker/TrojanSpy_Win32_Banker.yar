
rule TrojanSpy_Win32_Banker{
	meta:
		description = "TrojanSpy:Win32/Banker,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 55 51 4c 32 33 4b 4c 32 33 44 46 39 30 57 49 35 45 31 4a 41 53 34 36 37 4e 4d 43 58 58 4c 36 4a 41 4f 41 55 57 57 4d 43 4c 30 41 4f 4d 4d 34 41 34 56 5a 59 57 39 4b 48 4a 55 49 32 33 34 37 45 4a 48 4a 4b 44 46 33 34 32 34 53 4b 4c } //01 00  YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM4A4VZYW9KHJUI2347EJHJKDF3424SKL
		$a_81_1 = {42 42 32 34 34 42 41 46 43 46 33 37 35 43 39 30 45 34 32 45 35 30 41 36 44 46 32 44 36 38 38 39 45 35 32 33 35 31 42 33 43 46 32 32 34 31 34 30 34 30 34 30 42 36 33 44 42 31 33 38 41 33 44 42 32 37 34 37 42 46 33 37 34 31 41 37 43 43 } //00 00  BB244BAFCF375C90E42E50A6DF2D6889E52351B3CF2241404040B63DB138A3DB2747BF3741A7CC
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banker_2{
	meta:
		description = "TrojanSpy:Win32/Banker,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 42 4e 20 41 4d 52 4f 20 42 61 6e 6b } //01 00  ABN AMRO Bank
		$a_01_1 = {42 61 6e 63 6f 20 64 6f 20 4e 6f 72 64 65 73 74 65 20 42 72 61 73 69 6c 65 69 72 6f } //01 00  Banco do Nordeste Brasileiro
		$a_01_2 = {42 61 6e 63 6f 20 43 6f 6f 70 65 72 61 74 69 76 6f 20 64 6f 20 42 72 61 73 69 6c } //01 00  Banco Cooperativo do Brasil
		$a_01_3 = {42 61 6e 63 6f 20 64 6f 20 45 73 74 61 64 6f 20 64 65 20 50 65 72 6e 61 6d 62 75 63 6f } //01 00  Banco do Estado de Pernambuco
		$a_01_4 = {42 61 6e 63 6f 20 64 6f 20 45 73 74 61 64 6f 20 64 65 20 53 65 72 67 69 70 65 } //01 00  Banco do Estado de Sergipe
		$a_01_5 = {42 61 6e 63 6f 20 64 6f 20 45 73 74 61 64 6f 20 64 6f 20 50 61 72 61 6e } //01 00  Banco do Estado do Paran
		$a_01_6 = {42 61 6e 63 6f 20 64 6f 20 45 73 74 61 64 6f 20 64 6f 20 52 69 6f 20 47 72 61 6e 64 65 20 64 6f 20 53 75 6c } //01 00  Banco do Estado do Rio Grande do Sul
		$a_01_7 = {42 61 6e 63 6f 20 43 69 64 61 64 65 } //01 00  Banco Cidade
		$a_01_8 = {42 61 6e 63 6f 20 43 69 74 69 62 61 6e 6b } //01 00  Banco Citibank
		$a_01_9 = {42 61 6e 63 6f 20 43 72 65 64 69 62 65 6c } //01 00  Banco Credibel
		$a_01_10 = {42 61 6e 63 6f 20 44 61 79 63 6f 76 61 6c } //01 00  Banco Daycoval
		$a_01_11 = {42 61 6e 63 6f 20 64 6f 20 42 72 61 73 69 6c } //01 00  Banco do Brasil
		$a_01_12 = {48 53 42 43 20 42 61 6d 65 72 69 6e 64 75 73 } //01 00  HSBC Bamerindus
		$a_01_13 = {42 61 6e 63 6f 20 4d 65 72 63 61 6e 74 69 6c 20 64 6f 20 42 72 61 73 69 6c } //01 00  Banco Mercantil do Brasil
		$a_01_14 = {42 61 6e 63 6f 20 4e 6f 73 73 61 20 43 61 69 78 61 } //01 00  Banco Nossa Caixa
		$a_01_15 = {42 61 6e 63 6f 20 43 6f 6f 70 65 72 61 74 69 76 6f 20 53 49 43 52 45 44 49 } //01 00  Banco Cooperativo SICREDI
		$a_01_16 = {42 61 73 65 20 49 52 20 65 20 47 65 72 61 64 6f 72 20 64 65 20 49 4e 53 53 } //00 00  Base IR e Gerador de INSS
		$a_00_17 = {78 28 04 00 3c 00 3c 00 39 00 00 01 00 09 } //01 56 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banker_3{
	meta:
		description = "TrojanSpy:Win32/Banker,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 39 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 65 67 61 73 43 61 72 64 } //01 00  VegasCard
		$a_01_1 = {43 61 72 74 61 6f 45 76 61 6e 67 65 6c 69 63 6f } //01 00  CartaoEvangelico
		$a_01_2 = {4d 69 6e 61 73 63 72 65 64 } //01 00  Minascred
		$a_01_3 = {42 69 6c 68 65 74 65 20 55 6e 69 63 6f } //01 00  Bilhete Unico
		$a_01_4 = {42 61 6e 63 6f 20 50 61 6e 61 6d 65 72 69 63 61 6e 6f } //01 00  Banco Panamericano
		$a_01_5 = {43 68 65 63 6b 20 45 78 70 72 65 73 73 5f 32 } //01 00  Check Express_2
		$a_01_6 = {42 72 61 64 65 73 63 6f 20 50 72 69 76 61 74 65 } //01 00  Bradesco Private
		$a_01_7 = {43 61 62 61 6c 20 41 72 67 65 6e 74 69 6e 61 } //01 00  Cabal Argentina
		$a_01_8 = {42 61 6e 63 6f 20 50 72 6f 76 69 6e 63 69 61 6c } //01 00  Banco Provincial
		$a_01_9 = {41 6d 65 78 20 4d 65 78 69 63 6f } //01 00  Amex Mexico
		$a_01_10 = {42 72 61 73 69 6c 20 43 61 72 64 } //01 00  Brasil Card
		$a_01_11 = {54 65 6c 65 6e 65 74 } //01 00  Telenet
		$a_01_12 = {43 69 74 69 62 61 6e 6b } //01 00  Citibank
		$a_01_13 = {48 69 70 65 72 43 61 72 64 } //01 00  HiperCard
		$a_01_14 = {45 2d 43 61 70 74 75 72 65 } //01 00  E-Capture
		$a_01_15 = {41 63 63 6f 72 20 53 65 72 76 69 63 65 73 } //01 00  Accor Services
		$a_01_16 = {59 61 6d 61 64 61 } //01 00  Yamada
		$a_01_17 = {41 75 74 6f 72 69 7a 42 6f 6e 75 73 } //01 00  AutorizBonus
		$a_01_18 = {4d 75 6c 74 69 43 68 65 71 75 65 } //01 00  MultiCheque
		$a_01_19 = {4f 6e 6c 79 56 69 73 61 } //01 00  OnlyVisa
		$a_01_20 = {73 69 74 6f 6e 6c 79 76 69 73 61 2e 65 78 65 } //01 00  sitonlyvisa.exe
		$a_01_21 = {54 65 63 42 61 6e 20 4f 6e 4c 69 6e 65 } //01 00  TecBan OnLine
		$a_01_22 = {54 65 63 42 61 6e 20 48 6f 73 74 2d 48 6f 73 74 } //01 00  TecBan Host-Host
		$a_01_23 = {43 72 65 64 69 74 42 75 72 65 61 75 } //01 00  CreditBureau
		$a_01_24 = {52 6f 74 65 61 64 6f 72 20 64 65 20 43 6f 72 72 65 73 70 6f 6e 64 65 6e 74 65 20 42 61 6e 63 61 72 69 6f } //01 00  Roteador de Correspondente Bancario
		$a_01_25 = {42 4f 44 20 44 65 62 69 74 6f } //01 00  BOD Debito
		$a_01_26 = {42 4f 44 20 43 72 65 64 69 74 6f } //01 00  BOD Credito
		$a_01_27 = {50 61 79 53 6d 61 72 74 49 44 } //01 00  PaySmartID
		$a_01_28 = {42 72 61 7a 69 6c 69 61 6e 43 61 72 64 } //01 00  BrazilianCard
		$a_01_29 = {43 2e 42 2e 20 43 6f 72 62 61 6e 20 53 6f 66 74 77 61 72 65 20 45 78 70 72 65 73 73 } //01 00  C.B. Corban Software Express
		$a_01_30 = {73 69 74 65 70 61 79 67 69 66 74 } //01 00  sitepaygift
		$a_01_31 = {45 50 41 59 47 49 46 54 } //01 00  EPAYGIFT
		$a_01_32 = {53 69 74 42 61 6e 65 73 63 61 72 64 } //01 00  SitBanescard
		$a_01_33 = {42 41 4e 45 53 43 41 52 } //01 00  BANESCAR
		$a_01_34 = {41 6d 65 78 20 49 6e 74 65 72 6e 61 63 69 6f 6e 61 6c } //01 00  Amex Internacional
		$a_01_35 = {42 61 6e 63 6f 20 53 61 6e 74 6f 73 } //01 00  Banco Santos
		$a_01_36 = {43 68 65 71 75 65 20 43 61 72 64 61 70 69 6f } //01 00  Cheque Cardapio
		$a_01_37 = {41 73 73 6f 63 69 61 63 61 6f 20 43 6f 6d 65 72 63 69 61 6c 20 53 50 } //01 00  Associacao Comercial SP
		$a_01_38 = {73 69 74 77 61 79 75 70 2e 65 78 65 } //01 00  sitwayup.exe
		$a_01_39 = {73 69 74 63 61 72 74 6f 2e 65 78 65 } //01 00  sitcarto.exe
		$a_01_40 = {73 69 74 6f 6e 65 62 6f 78 2e 65 78 65 } //01 00  sitonebox.exe
		$a_01_41 = {73 69 74 6d 61 78 78 69 63 61 72 64 2e 65 78 65 } //01 00  sitmaxxicard.exe
		$a_01_42 = {73 69 74 70 61 79 73 6d 61 72 74 69 64 2e 65 78 65 } //01 00  sitpaysmartid.exe
		$a_01_43 = {73 69 74 67 6c 6f 62 61 6c 73 61 75 64 65 2e 65 78 65 } //01 00  sitglobalsaude.exe
		$a_01_44 = {73 69 74 63 61 72 64 73 65 2e 65 78 65 } //01 00  sitcardse.exe
		$a_01_45 = {73 69 74 62 61 6e 63 72 65 64 2e 65 78 65 } //01 00  sitbancred.exe
		$a_01_46 = {73 69 74 73 69 6d 63 72 65 64 2e 65 78 65 } //01 00  sitsimcred.exe
		$a_01_47 = {73 69 74 76 69 73 61 70 61 73 73 66 69 72 73 74 2e 65 78 65 } //01 00  sitvisapassfirst.exe
		$a_01_48 = {73 69 6d 63 6f 6d 75 69 6e 63 6f 6d 6d 2e 65 78 65 } //01 00  simcomuincomm.exe
		$a_01_49 = {73 69 74 69 6e 63 6f 6d 6d 2e 65 78 65 } //01 00  sitincomm.exe
		$a_01_50 = {73 69 74 6c 74 6d 72 61 69 7a 65 6e 2e 65 78 65 } //01 00  sitltmraizen.exe
		$a_01_51 = {73 69 6d 63 6f 6d 75 6d 65 78 69 63 6f 70 72 6f 73 61 2e 65 78 65 } //01 00  simcomumexicoprosa.exe
		$a_01_52 = {53 65 72 61 73 61 20 41 75 74 6f 72 69 7a 61 64 6f 72 20 43 72 65 64 69 74 6f } //01 00  Serasa Autorizador Credito
		$a_01_53 = {42 61 6e 63 6f 20 47 45 20 43 61 70 69 74 61 6c } //01 00  Banco GE Capital
		$a_01_54 = {43 61 72 74 61 6f 20 50 72 65 73 65 6e 74 65 20 4d 61 72 69 73 61 } //01 00  Cartao Presente Marisa
		$a_01_55 = {42 61 6e 63 6f 20 50 6f 74 74 65 6e 63 69 61 6c } //9c ff  Banco Pottencial
		$a_01_56 = {2f 73 69 74 65 66 2f 2e 2f 63 6f 6e 66 69 67 2f 73 69 74 65 66 2e 69 6e 69 } //00 00  /sitef/./config/sitef.ini
		$a_00_57 = {7e 15 00 00 00 05 da 12 46 69 71 9f 1b 34 90 60 ee 43 be 12 00 00 00 00 62 7e 15 00 00 01 31 56 03 59 89 f9 f3 09 f5 82 32 d0 6a 87 5f 00 00 00 00 62 7e 15 00 00 02 57 } //7b 85 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banker_4{
	meta:
		description = "TrojanSpy:Win32/Banker,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 69 75 7a 68 65 2e 63 6f 6d 2f 64 64 76 61 6e 2e 65 78 65 } //01 00  http://www.xiuzhe.com/ddvan.exe
		$a_01_1 = {75 73 65 72 69 64 3d } //01 00  userid=
		$a_01_2 = {70 61 73 73 77 6f 72 64 3d } //01 00  password=
		$a_01_3 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 } //01 00  C:\windows\sysinfo.ini
		$a_01_4 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 65 00 62 00 78 00 31 00 65 00 31 00 2e 00 65 00 78 00 65 00 } //00 00  C:\windows\ebx1e1.exe
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banker_5{
	meta:
		description = "TrojanSpy:Win32/Banker,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //01 00  Software\Borland\Delphi\Locales
		$a_01_1 = {64 73 50 72 6f 78 79 44 65 74 65 63 74 69 6e 67 } //01 00  dsProxyDetecting
		$a_01_2 = {52 43 50 54 20 54 4f } //01 00  RCPT TO
		$a_01_3 = {4d 41 49 4c 20 46 52 4f 4d } //01 00  MAIL FROM
		$a_01_4 = {6d 79 73 71 6c 31 2e 31 30 30 77 73 2e 63 6f 6d } //01 00  mysql1.100ws.com
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_6 = {57 53 41 41 73 79 6e 63 47 65 74 48 6f 73 74 42 79 4e 61 6d 65 } //01 00  WSAAsyncGetHostByName
		$a_01_7 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00  GetClipboardData
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banker_6{
	meta:
		description = "TrojanSpy:Win32/Banker,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 5c 42 41 54 4c 45 5f 53 4f 55 52 43 45 5c 53 61 6d 70 6c 65 53 65 72 76 69 63 65 5f 72 75 6e 5f 73 68 65 6c 6c 63 6f 64 65 5f 66 72 6f 6d 2d 6d 65 6d 6f 72 79 31 30 2d 30 32 2d 32 30 31 36 5c 52 65 6c 65 61 73 65 5c 53 61 6d 70 6c 65 53 65 72 76 69 63 65 2e 70 64 62 } //01 00  shell\BATLE_SOURCE\SampleService_run_shellcode_from-memory10-02-2016\Release\SampleService.pdb
		$a_01_1 = {4a 00 41 00 56 00 41 00 3a 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 43 00 74 00 72 00 6c 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 3a 00 20 00 53 00 45 00 52 00 56 00 49 00 43 00 45 00 5f 00 43 00 4f 00 4e 00 54 00 52 00 4f 00 4c 00 5f 00 53 00 54 00 4f 00 50 00 20 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 } //01 00  JAVA: ServiceCtrlHandler: SERVICE_CONTROL_STOP Request
		$a_01_2 = {55 73 65 72 73 5c 44 4e 53 5c 44 6f 63 75 6d 65 6e 74 73 5c } //00 00  Users\DNS\Documents\
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banker_7{
	meta:
		description = "TrojanSpy:Win32/Banker,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //01 00  Software\Borland\Delphi\Locales
		$a_01_1 = {59 6f 75 72 46 69 6c 65 48 6f 73 74 2e 63 6f 6d } //01 00  YourFileHost.com
		$a_01_2 = {48 6f 73 74 46 69 6c 65 7a 2e 63 6f 6d } //01 00  HostFilez.com
		$a_01_3 = {75 70 64 61 74 65 72 2e 64 6c 6c } //01 00  updater.dll
		$a_01_4 = {61 75 64 69 6f 68 71 2e 65 78 65 } //01 00  audiohq.exe
		$a_01_5 = {63 3a 5c 61 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 20 20 68 74 74 70 3a 2f 2f 77 77 77 2e 79 6f 75 74 75 62 65 2e 63 6f 6d 2f 77 61 74 63 68 3f 76 3d 56 6a 70 37 76 67 6a 31 31 39 73 } //01 00  c:\arquivos de programas\internet explorer\iexplore.exe   http://www.youtube.com/watch?v=Vjp7vgj119s
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  UnhookWindowsHookEx
		$a_01_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}