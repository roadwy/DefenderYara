
rule Trojan_BAT_Crinoka_A{
	meta:
		description = "Trojan:BAT/Crinoka.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 63 70 66 6c 6f 6f 64 00 74 63 70 62 79 70 61 73 73 00 74 63 70 63 6f 6e 6e 65 63 74 00 74 63 70 45 78 68 61 75 73 74 00 } //2
		$a_01_1 = {43 72 69 6e 6f 2e 41 63 74 69 6f 6e 73 } //1 Crino.Actions
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 WindowsUpdater.exe
		$a_01_4 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 2e 00 65 00 78 00 65 00 } //1 \AppData\Roaming\kernel.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}