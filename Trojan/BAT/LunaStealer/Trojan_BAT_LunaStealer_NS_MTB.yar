
rule Trojan_BAT_LunaStealer_NS_MTB{
	meta:
		description = "Trojan:BAT/LunaStealer.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0d 00 00 "
		
	strings :
		$a_81_0 = {4b 65 79 6c 6f 67 67 65 72 } //2 Keylogger
		$a_81_1 = {45 4e 43 52 59 50 54 45 44 3a 43 50 42 37 74 69 30 41 35 7a 61 73 2f 30 64 46 34 58 42 4b 7a 44 69 55 49 66 6d 51 35 52 67 72 4c 51 76 44 72 59 43 53 54 34 4d 3d } //1 ENCRYPTED:CPB7ti0A5zas/0dF4XBKzDiUIfmQ5RgrLQvDrYCST4M=
		$a_81_2 = {45 4e 43 52 59 50 54 45 44 3a 63 59 73 36 4b 53 52 79 4f 33 79 4d 72 57 47 51 44 4f 6d 4b 78 69 76 6a 43 56 78 52 48 50 38 58 32 65 6c 58 51 74 64 52 47 62 69 61 64 31 66 46 6b 56 33 44 42 49 48 4b 32 45 62 75 49 42 44 41 } //1 ENCRYPTED:cYs6KSRyO3yMrWGQDOmKxivjCVxRHP8X2elXQtdRGbiad1fFkV3DBIHK2EbuIBDA
		$a_81_3 = {41 6e 74 69 41 6e 61 6c 79 73 69 73 } //1 AntiAnalysis
		$a_81_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 passwords.txt
		$a_81_6 = {6b 6c 66 68 62 64 6e 6c 63 66 63 61 63 63 6f 61 6b 68 63 65 6f 64 68 6c 64 6a 6f 6a 62 6f 67 61 } //1 klfhbdnlcfcaccoakhceodhldjojboga
		$a_81_7 = {65 6a 62 61 6c 62 61 6b 6f 70 6c 63 68 6c 67 68 65 63 64 61 6c 6d 65 65 65 61 6a 6e 69 6d 68 6d } //1 ejbalbakoplchlghecdalmeeeajnimhm
		$a_81_8 = {6f 6f 6f 69 62 6c 62 64 70 64 6c 65 63 69 67 6f 64 6e 64 69 6e 62 70 66 6f 70 6f 6d 61 65 67 6c } //1 oooiblbdpdlecigodndinbpfopomaegl
		$a_81_9 = {61 61 6e 6a 68 67 69 61 6d 6e 61 63 64 66 6e 6c 66 6e 6d 67 65 68 6a 69 6b 61 67 64 62 61 66 64 } //1 aanjhgiamnacdfnlfnmgehjikagdbafd
		$a_81_10 = {61 6b 6f 69 61 69 62 6e 65 70 63 65 64 63 70 6c 69 6a 6d 69 61 6d 6e 61 69 67 62 65 70 6d 63 62 } //1 akoiaibnepcedcplijmiamnaigbepmcb
		$a_81_11 = {61 6a 6b 68 6f 65 69 69 6f 6b 69 67 68 6c 6d 64 6e 6c 61 6b 70 6a 66 6f 6f 62 6e 6a 69 6e 69 65 } //1 ajkhoeiiokighlmdnlakpjfoobnjinie
		$a_81_12 = {64 6d 64 69 6d 61 70 66 67 68 61 61 6b 65 69 62 70 70 62 66 65 6f 6b 68 67 6f 69 6b 65 6f 63 69 } //1 dmdimapfghaakeibppbfeokhgoikeoci
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=14
 
}