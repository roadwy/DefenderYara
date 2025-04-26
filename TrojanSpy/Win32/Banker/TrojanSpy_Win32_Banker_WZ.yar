
rule TrojanSpy_Win32_Banker_WZ{
	meta:
		description = "TrojanSpy:Win32/Banker.WZ,SIGNATURE_TYPE_PEHSTR,29 00 29 00 12 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 62 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 30 29 } //10 Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)
		$a_01_2 = {64 65 6c 20 64 65 6c 65 78 65 63 2e 62 61 74 } //10 del delexec.bat
		$a_01_3 = {69 6e 73 65 72 74 20 69 6e 74 6f 20 63 6c 69 65 6e 74 65 73 } //10 insert into clientes
		$a_01_4 = {6a 75 73 74 74 62 62 61 62 79 2e 63 6f 6d 2f 6a 73 2f } //1 justtbbaby.com/js/
		$a_01_5 = {77 77 77 2e 67 75 61 6e 74 61 6e 61 6d 65 72 61 2e 6f 72 67 2e 62 72 2f 66 6f 74 6f 73 2f } //1 www.guantanamera.org.br/fotos/
		$a_01_6 = {63 61 74 6f 6c 69 63 61 6e 65 74 2e 6e 65 74 2f 69 6d 61 67 65 73 2f } //1 catolicanet.net/images/
		$a_01_7 = {65 75 67 65 6e 69 61 2d 6a 6f 72 67 65 2e 63 6f 6d 2f 6a 73 2f } //1 eugenia-jorge.com/js/
		$a_01_8 = {65 73 70 65 72 61 6c 69 6d 65 6e 74 6f 73 6d 65 2e 63 6f 6d 2e 62 72 2f 6a 73 } //1 esperalimentosme.com.br/js
		$a_01_9 = {6c 61 70 69 6d 65 70 70 2e 63 6f 6d 2f 6a 73 2f } //1 lapimepp.com/js/
		$a_01_10 = {77 77 77 2e 72 61 6a 6b 6f 74 63 68 61 6d 62 65 72 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f } //1 www.rajkotchamber.com/images/
		$a_01_11 = {77 77 77 2e 66 6f 72 6d 61 6e 64 6f 73 75 6e 69 64 66 2e 63 6f 6d 2f 66 6f 74 6f 73 2f } //1 www.formandosunidf.com/fotos/
		$a_01_12 = {77 77 77 2e 66 75 6e 64 61 63 69 6f 6e 61 73 69 6c 6f 2e 63 6f 6d 2f 53 63 72 69 70 74 73 2f } //1 www.fundacionasilo.com/Scripts/
		$a_01_13 = {77 77 77 2e 6a 70 78 2d 61 72 71 2e 63 6f 6d 2f 73 74 61 66 66 2f } //1 www.jpx-arq.com/staff/
		$a_01_14 = {77 77 77 2e 70 72 6f 6e 61 75 74 69 2e 63 6f 6d 2f 6c 6f 6a 61 2f 69 6e 63 6c 75 64 65 73 2f 6d 6f 64 75 6c 65 73 2f } //1 www.pronauti.com/loja/includes/modules/
		$a_01_15 = {74 68 61 74 73 64 65 73 69 67 6e 2e 69 74 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 73 2f } //1 thatsdesign.it/wp-includes/js/
		$a_01_16 = {77 77 77 2e 63 69 6e 65 74 2e 69 74 2f 6a 73 2f } //1 www.cinet.it/js/
		$a_01_17 = {77 77 77 2e 61 73 74 75 72 6d 65 64 2e 6f 72 67 2f 69 6e 64 65 78 5f 61 72 63 68 69 76 6f 73 2f } //1 www.asturmed.org/index_archivos/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=41
 
}