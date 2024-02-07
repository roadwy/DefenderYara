
rule TrojanSpy_Win32_Bancos_ZI{
	meta:
		description = "TrojanSpy:Win32/Bancos.ZI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0b 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 61 74 61 3d 90 02 06 26 75 73 65 72 4e 61 6d 65 3d 25 73 26 63 6f 6d 70 4e 61 6d 65 3d 25 73 90 00 } //01 00 
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_2 = {2f 73 6f 70 68 69 61 2f 69 6e 66 6f 34 31 2e 70 68 70 } //01 00  /sophia/info41.php
		$a_00_3 = {53 6f 70 68 69 61 5c 52 65 6c 65 61 73 65 5c 53 6f 70 68 69 61 2e 70 64 62 } //01 00  Sophia\Release\Sophia.pdb
		$a_00_4 = {25 73 5c 47 62 50 6c 75 67 69 6e 5c 42 62 5c 25 73 } //01 00  %s\GbPlugin\Bb\%s
		$a_00_5 = {2e 62 62 2e 63 6f 6d 2e 62 72 } //01 00  .bb.com.br
		$a_00_6 = {6e 6f 74 69 63 69 61 2e 62 62 } //01 00  noticia.bb
		$a_00_7 = {2f 69 6e 63 6c 75 64 65 73 2f 6a 73 2f 63 6f 6e 74 72 6f 6c 65 2e 6a 73 } //01 00  /includes/js/controle.js
		$a_00_8 = {70 6f 73 74 2e 73 72 66 } //01 00  post.srf
		$a_00_9 = {64 61 74 61 3d 68 6f 74 6d 61 69 6c 26 75 73 65 72 4e 61 6d 65 3d 25 73 26 63 6f 6d 70 4e 61 6d 65 3d 25 73 26 70 6f 73 74 3d 25 73 } //01 00  data=hotmail&userName=%s&compName=%s&post=%s
		$a_00_10 = {53 6f 70 68 69 61 44 4c 4c 5c 52 65 6c 65 61 73 65 5c 53 6f 70 68 69 61 44 4c 4c 2e 70 64 62 } //00 00  SophiaDLL\Release\SophiaDLL.pdb
	condition:
		any of ($a_*)
 
}