
rule Trojan_O97M_Donoff_RK_MTB{
	meta:
		description = "Trojan:O97M/Donoff.RK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 63 6c 65 61 6e 22 } //1 Attribute VB_Name = "clean"
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 28 22 30 30 30 30 34 35 33 35 35 34 34 34 2d 45 39 34 41 2d 45 43 31 31 2d 39 37 32 43 2d 30 32 36 39 30 37 33 31 3a 77 65 6e 22 29 29 } //1 GetObject(StrReverse("000045355444-E94A-EC11-972C-02690731:wen"))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_O97M_Donoff_RK_MTB_2{
	meta:
		description = "Trojan:O97M/Donoff.RK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 20 3d 20 73 20 2b 20 22 53 68 65 22 20 2b 20 22 6c 6c 5c 76 31 2e 30 22 20 2b 20 22 5c 70 6f 77 22 20 2b 20 22 65 72 73 68 22 20 2b 20 22 65 6c 6c 2e 22 20 2b 20 22 65 78 65 22 } //1 s = s + "She" + "ll\v1.0" + "\pow" + "ersh" + "ell." + "exe"
		$a_01_1 = {73 20 3d 20 73 20 2b 20 22 20 2d 77 69 6e 20 22 20 2b 20 22 31 20 2d 65 22 20 2b 20 22 6e 63 20 22 } //1 s = s + " -win " + "1 -e" + "nc "
		$a_01_2 = {73 20 3d 20 73 20 2b 20 22 2f 4d 49 22 20 2b 20 22 4e 20 43 3a 5c 57 69 22 20 2b 20 22 6e 64 6f 22 } //1 s = s + "/MI" + "N C:\Wi" + "ndo"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_O97M_Donoff_RK_MTB_3{
	meta:
		description = "Trojan:O97M/Donoff.RK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 75 62 20 68 65 6c 6c 6f 57 6f 72 64 28 29 0d 0a 20 20 20 20 53 65 74 20 6f 62 6a 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 43 30 38 41 46 44 39 30 2d 46 32 41 31 2d 31 31 44 31 2d 38 34 35 35 2d 30 30 41 30 43 39 31 46 33 38 38 30 22 29 } //1
		$a_03_1 = {44 69 6d 20 [0-0f] 0d 0a 20 20 20 20 90 1b 00 20 3d 20 22 68 22 20 26 20 22 65 22 20 26 20 22 6c 22 20 26 20 22 6c 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}