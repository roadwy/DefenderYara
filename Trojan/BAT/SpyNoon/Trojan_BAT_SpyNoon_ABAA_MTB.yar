
rule Trojan_BAT_SpyNoon_ABAA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ABAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 4d 65 6e 75 20 53 74 61 72 74 5c 50 72 6f 67 72 61 6d 6d 69 5c 45 73 65 63 75 7a 69 6f 6e 65 20 41 75 74 6f 6d 61 74 69 63 61 5c 64 72 69 76 65 72 73 68 61 6e 64 6c 65 72 73 2e 65 78 65 } //C:\ProgramData\Microsoft\Windows\Menu Start\Programmi\Esecuzione Automatica\drivershandlers.exe  1
		$a_80_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 64 72 69 76 65 72 73 68 61 6e 64 6c 65 72 73 2e 65 78 65 } //C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\drivershandlers.exe  1
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 74 61 72 74 75 70 41 70 70 72 6f 76 65 64 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run  1
		$a_80_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_4 = {43 3a 5c 55 73 65 72 73 5c 4e 65 6b 6f 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 63 61 72 74 65 6c 6c 61 74 6f 72 5c 63 61 72 74 65 6c 6c 61 74 6f 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 63 61 72 74 65 6c 6c 61 74 6f 72 65 72 2e 70 64 62 } //C:\Users\Neko\Documents\Visual Studio 2015\Projects\cartellator\cartellator\obj\Debug\cartellatorer.pdb  1
		$a_80_5 = {63 61 72 74 65 6c 6c 61 74 6f 72 65 72 2e 65 78 65 } //cartellatorer.exe  1
		$a_80_6 = {66 62 61 30 65 30 30 62 34 30 39 63 64 32 31 62 38 30 31 34 63 63 64 32 31 35 34 36 38 36 39 37 33 32 30 37 30 37 32 36 66 36 37 37 32 36 31 36 64 32 30 36 33 36 31 36 65 36 65 36 66 37 34 32 30 36 32 36 35 32 30 37 32 37 35 36 65 32 30 36 39 36 65 32 30 34 34 34 66 35 33 32 30 36 64 36 66 36 34 36 35 32 65 30 64 30 64 30 61 32 34 } //fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a24  1
		$a_80_7 = {63 61 72 74 65 6c 6c 61 74 6f 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //cartellator.Form1.resources  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}