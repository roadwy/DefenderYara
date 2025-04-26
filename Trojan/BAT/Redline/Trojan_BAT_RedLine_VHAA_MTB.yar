
rule Trojan_BAT_RedLine_VHAA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.VHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 66 43 70 6c 67 73 44 43 72 45 59 50 7a 48 68 4d 43 4c 62 6c 73 79 5a 78 74 61 71 2e 64 6c 6c } //2 hfCplgsDCrEYPzHhMCLblsyZxtaq.dll
		$a_01_1 = {56 49 74 59 6b 45 70 6f 52 66 43 4e 6a 44 69 51 63 4a 49 4d 7a 78 47 54 49 64 } //1 VItYkEpoRfCNjDiQcJIMzxGTId
		$a_01_2 = {71 6a 54 59 70 6e 77 46 64 76 63 4f 77 75 49 77 43 4f 48 79 51 6b 55 41 6d 51 6b 2e 64 6c 6c } //1 qjTYpnwFdvcOwuIwCOHyQkUAmQk.dll
		$a_01_3 = {55 76 77 68 6d 78 53 73 72 4d 58 4f 58 77 5a 64 6a 63 51 5a 56 58 69 6b } //1 UvwhmxSsrMXOXwZdjcQZVXik
		$a_01_4 = {54 48 6b 69 46 6c 68 68 6c 6b 4a 48 63 48 72 59 43 61 50 47 79 5a 56 66 48 2e 64 6c 6c } //1 THkiFlhhlkJHcHrYCaPGyZVfH.dll
		$a_01_5 = {4d 73 62 79 46 48 77 49 57 6a 6e 6e 67 46 48 50 47 59 57 } //1 MsbyFHwIWjnngFHPGYW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}