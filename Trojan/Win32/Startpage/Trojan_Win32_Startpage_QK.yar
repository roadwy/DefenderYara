
rule Trojan_Win32_Startpage_QK{
	meta:
		description = "Trojan:Win32/Startpage.QK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 49 6e 74 65 72 6e 61 74 20 45 78 6c 70 6f 72 65 72 2e 6c 6e 6b 22 20 2f 79 } //4 \Internat Exlporer.lnk" /y
		$a_01_1 = {6f 55 72 6c 4c 69 6e 6b 2e 54 61 72 67 65 74 50 61 74 68 20 3d 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 79 75 79 75 2e 63 6f 6d 2f 3f 66 61 76 32 22 } //4 oUrlLink.TargetPath = "http://www.yuyu.com/?fav2"
		$a_01_2 = {57 53 48 53 68 65 6c 6c 2e 53 65 6e 64 4b 65 79 73 20 22 7b 46 35 7d 22 } //3 WSHShell.SendKeys "{F5}"
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=11
 
}