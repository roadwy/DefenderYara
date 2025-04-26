
rule TrojanSpy_Win32_Banker_AHH{
	meta:
		description = "TrojanSpy:Win32/Banker.AHH,SIGNATURE_TYPE_PEHSTR_EXT,54 01 40 01 08 00 00 "
		
	strings :
		$a_01_0 = {74 78 74 70 61 73 73 77 64 2e 76 61 6c 75 65 3d 70 77 64 65 6b 61 } //100 txtpasswd.value=pwdeka
		$a_01_1 = {70 61 72 65 6e 74 2e 70 61 72 65 6e 74 2e 44 75 6d 6d 79 2e 67 65 74 70 77 64 28 29 } //100 parent.parent.Dummy.getpwd()
		$a_01_2 = {3c 73 63 72 69 70 74 3e 77 69 6e 64 6f 77 2e 6c 6f 63 61 74 69 6f 6e 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 61 6e 74 61 6e 64 65 72 6e 65 74 } //100 <script>window.location = "https://www.santandernet
		$a_01_3 = {2e 64 6f 63 75 6d 65 6e 74 2e 66 72 6d 45 6e 76 69 61 72 2e 74 78 74 45 6b 61 2e 76 61 6c 75 65 3d 45 6b 61 3b } //10 .document.frmEnviar.txtEka.value=Eka;
		$a_01_4 = {44 6c 6c 73 61 69 6e 74 61 6e 67 65 72 63 5c 52 65 6c 65 61 73 65 } //10 Dllsaintangerc\Release
		$a_01_5 = {32 30 35 2e 32 33 34 2e 31 33 34 2e 31 30 32 00 31 2e 30 2e 30 2e 30 } //10
		$a_01_6 = {66 4d 65 6e 75 2e 41 62 72 65 50 61 67 69 6e 61 28 32 37 37 33 29 3b 3c 2f 73 63 72 69 70 74 3e } //10 fMenu.AbrePagina(2773);</script>
		$a_01_7 = {63 68 65 63 61 41 6c 74 75 72 61 28 29 7b 7d 3b 3c 2f 73 63 72 69 70 74 } //10 checaAltura(){};</script
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10) >=320
 
}