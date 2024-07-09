
rule Trojan_Win32_Redline_DAB_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 2f ?? 47 e2 } //3
		$a_01_1 = {6e 6c 61 68 4a 59 6c 61 77 55 5a 69 66 79 54 70 4f 6e 77 50 6e 75 4d 46 58 46 65 5a 63 53 53 4e 57 59 } //1 nlahJYlawUZifyTpOnwPnuMFXFeZcSSNWY
		$a_01_2 = {72 7a 47 62 59 43 47 76 64 73 74 65 4b 77 4b 6f 57 5a 69 62 6f 68 41 53 45 6f 77 64 42 75 49 52 } //1 rzGbYCGvdsteKwKoWZibohASEowdBuIR
		$a_01_3 = {71 72 4a 75 61 5a 42 62 58 4d 41 41 7a 55 4f 6f 6a 46 5a 7a 57 50 76 52 53 66 46 47 77 77 7a 78 6d 67 } //1 qrJuaZBbXMAAzUOojFZzWPvRSfFGwwzxmg
		$a_01_4 = {72 68 76 45 75 59 68 4f 75 77 62 65 48 53 75 69 65 4e 77 52 73 7a 51 69 49 71 56 54 56 49 50 41 70 } //1 rhvEuYhOuwbeHSuieNwRszQiIqVTVIPAp
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}