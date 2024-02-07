
rule Trojan_Win32_Startpage_AEI{
	meta:
		description = "Trojan:Win32/Startpage.AEI,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 49 6e 73 65 72 74 62 7a 2e 61 73 70 78 3f 6d 63 69 3d } //02 00  /Insertbz.aspx?mci=
		$a_01_1 = {66 69 72 73 74 75 72 6c } //02 00  firsturl
		$a_01_2 = {53 65 72 76 65 72 49 44 } //01 00  ServerID
		$a_01_3 = {5c 77 69 6e 6d 73 61 67 65 6e 74 5c } //01 00  \winmsagent\
		$a_01_4 = {5c 65 6c 6e 6b 2e 6c 6e 6b } //01 00  \elnk.lnk
		$a_01_5 = {43 6f 6e 66 69 67 2e 69 6e 69 } //01 00  Config.ini
		$a_01_6 = {77 69 6e 72 75 6e 2e 69 63 6f } //01 00  winrun.ico
		$a_01_7 = {77 69 6e 6d 73 33 32 2e 70 63 75 } //01 00  winms32.pcu
		$a_01_8 = {65 72 75 6e 2e 66 7a 78 } //01 00  erun.fzx
		$a_01_9 = {73 65 74 75 70 77 65 62 2e 65 78 65 } //00 00  setupweb.exe
	condition:
		any of ($a_*)
 
}