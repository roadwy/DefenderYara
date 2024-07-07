
rule VirTool_Win32_Injector_AA{
	meta:
		description = "VirTool:Win32/Injector.AA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {50 68 00 00 00 00 68 00 00 00 00 ff 75 90 01 01 68 00 e1 f5 05 68 00 00 00 00 ff 75 90 01 01 ff 15 90 00 } //3
		$a_03_1 = {8b 48 3c 8b 4c 01 50 a3 90 01 03 00 89 0d 90 01 03 00 03 c8 89 0d 90 00 } //1
		$a_03_2 = {68 40 00 00 00 68 00 10 00 00 68 00 87 93 03 68 00 00 00 00 ff 75 90 01 01 ff 15 90 00 } //1
		$a_00_3 = {64 6f 63 75 6d 65 6e 74 2e 62 6f 64 79 2e 69 6e 6e 65 72 48 54 4d 4c 3d 27 3c 62 72 2f 3e 3c 66 6f 72 6d 20 4e 41 4d 45 3d 50 72 69 46 6f 72 6d 20 69 64 3d 22 50 72 69 46 6f 72 6d 22 20 6d 65 74 68 6f 64 3d 22 70 6f 73 74 22 20 41 43 54 49 4f 4e 20 3d } //1 document.body.innerHTML='<br/><form NAME=PriForm id="PriForm" method="post" ACTION =
		$a_00_4 = {3a 5c 53 56 4e 5c 33 36 30 74 63 70 76 69 65 77 5c 52 65 6c 65 61 73 65 5c 33 36 30 54 63 70 56 69 65 77 2e 70 64 62 } //1 :\SVN\360tcpview\Release\360TcpView.pdb
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}