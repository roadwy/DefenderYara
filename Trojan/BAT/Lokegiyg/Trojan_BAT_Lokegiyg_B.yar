
rule Trojan_BAT_Lokegiyg_B{
	meta:
		description = "Trojan:BAT/Lokegiyg.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 00 52 00 41 00 4e 00 4f 00 4e 00 43 00 45 00 2e 00 54 00 52 00 55 00 45 00 } //1 \RANONCE.TRUE
		$a_01_1 = {2d 00 2d 00 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 } //1 --config 
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_3 = {53 00 6b 00 79 00 70 00 65 00 20 00 50 00 6f 00 72 00 74 00 61 00 62 00 6c 00 65 00 } //1 Skype Portable
		$a_01_4 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_03_5 = {1f 1d 12 00 1a 28 ?? 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}