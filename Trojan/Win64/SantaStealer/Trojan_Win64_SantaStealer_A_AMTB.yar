
rule Trojan_Win64_SantaStealer_A_AMTB{
	meta:
		description = "Trojan:Win64/SantaStealer.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 74 65 61 6c 65 72 } //2 Stealer
		$a_81_1 = {33 31 2e 35 37 2e 33 38 2e 32 34 34 } //2 31.57.38.244
		$a_81_2 = {38 30 2e 37 36 2e 34 39 2e 31 31 34 } //2 80.76.49.114
		$a_81_3 = {42 72 6f 77 73 65 72 53 75 6d 6d 61 72 79 2e 74 78 74 } //1 BrowserSummary.txt
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 20 48 69 73 74 6f 72 79 } //1 Download History
		$a_81_5 = {63 6f 6e 66 69 67 5c 6c 6f 67 69 6e 75 73 65 72 73 } //1 config\loginusers
		$a_81_6 = {43 68 72 6f 6d 65 7c 55 73 65 72 20 44 61 74 61 } //1 Chrome|User Data
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}