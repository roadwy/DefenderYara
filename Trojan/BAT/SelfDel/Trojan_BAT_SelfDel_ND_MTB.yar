
rule Trojan_BAT_SelfDel_ND_MTB{
	meta:
		description = "Trojan:BAT/SelfDel.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 3d 00 00 70 72 4c 01 00 70 1a 1f 30 28 5e 00 00 0a 1c 33 18 04 17 6f ?? 00 00 0a 02 28 ?? 00 00 0a 73 ?? 00 00 06 6f ?? 00 00 06 2a 04 17 6f ?? 00 00 0a 2a } //3
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {2f 43 20 74 69 6d 65 6f 75 74 20 2f 54 20 32 20 2f 6e 6f 62 72 65 61 6b 20 3e 6e 75 6c 20 26 20 64 65 6c } //1 /C timeout /T 2 /nobreak >nul & del
		$a_01_3 = {6d 73 69 6e 66 6f 33 32 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 msinfo32.g.resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}