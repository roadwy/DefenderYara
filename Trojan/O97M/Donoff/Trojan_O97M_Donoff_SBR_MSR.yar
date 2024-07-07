
rule Trojan_O97M_Donoff_SBR_MSR{
	meta:
		description = "Trojan:O97M/Donoff.SBR!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 65 72 25 75 25 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 2e 65 78 65 } //5 C:\Windows\System32\cer%u%.exe C:\ProgramData\1.exe
	condition:
		((#a_00_0  & 1)*5) >=5
 
}
rule Trojan_O97M_Donoff_SBR_MSR_2{
	meta:
		description = "Trojan:O97M/Donoff.SBR!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 65 72 74 69 6c 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4f 49 55 54 46 75 79 22 2c 20 54 72 75 65 29 } //1 Hertil.CreateTextFile("C:\ProgramData\OIUTFuy", True)
		$a_00_1 = {48 65 72 74 69 6c 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 54 72 65 73 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 } //1 Hertil.CreateTextFile(Trest.DefaultTargetFrame
		$a_00_2 = {61 2e 57 72 69 74 65 4c 69 6e 65 20 4c 6f 73 74 2e 44 72 6f 6b 73 } //1 a.WriteLine Lost.Droks
		$a_00_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 51 75 69 74 20 53 61 76 65 43 68 61 6e 67 65 73 } //1 Application.Quit SaveChanges
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_O97M_Donoff_SBR_MSR_3{
	meta:
		description = "Trojan:O97M/Donoff.SBR!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {62 61 63 2e 90 02 10 3d 6c 3f 70 68 70 2e 70 32 33 69 30 6f 69 61 2f 35 38 6f 6c 30 32 65 77 2f 6d 6f 63 2e 90 02 10 2f 2f 3a 70 74 74 68 90 00 } //3
		$a_03_1 = {63 6f 6d 2f 77 31 6b 62 73 37 71 66 66 77 72 33 67 35 6e 6e 2f 68 7a 31 37 30 34 69 38 6b 38 62 77 68 79 6f 31 2e 70 68 70 3f 6c 3d 90 02 10 2e 63 61 62 90 00 } //3
		$a_00_2 = {28 22 74 65 6d 70 22 29 20 26 20 22 5c 64 65 66 61 75 6c 74 2e 74 6d 70 } //2 ("temp") & "\default.tmp
		$a_00_3 = {53 68 65 6c 6c 20 22 72 65 67 73 76 72 33 32 2e 65 78 65 20 43 3a 5c 5c 55 73 65 72 73 5c 5c 50 75 62 6c 69 63 5c 5c 64 65 73 74 32 2e 64 6c 6c } //2 Shell "regsvr32.exe C:\\Users\\Public\\dest2.dll
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=5
 
}
rule Trojan_O97M_Donoff_SBR_MSR_4{
	meta:
		description = "Trojan:O97M/Donoff.SBR!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 67 61 6d 6d 61 73 6f 6c 75 74 69 6f 6e 73 6c 74 64 2e 63 6f 6d } //1 http://gammasolutionsltd.com
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 6f 75 64 68 65 69 62 2e 61 65 2f 64 66 66 62 75 68 75 } //1 http://www.boudheib.ae/dffbuhu
		$a_00_2 = {68 74 74 70 3a 2f 2f 62 61 73 65 6d 65 6e 74 70 75 62 6c 69 63 61 74 69 6f 6e 73 2e 63 6f 6d 2f 6b 6e 75 70 76 6d 78 } //1 http://basementpublications.com/knupvmx
		$a_00_3 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 73 74 6f 72 79 2e 69 6e 2f 6e 65 63 65 70 73 77 } //1 http://searchstory.in/necepsw
		$a_00_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 75 6c 74 72 61 61 63 74 69 6f 6e 2e 63 6f 6d 2e 62 72 2f 66 63 78 69 79 73 79 74 69 7a 6c 67 } //1 http://www.ultraaction.com.br/fcxiysytizlg
		$a_00_5 = {68 74 74 70 3a 2f 2f 70 61 64 67 65 74 74 63 6f 6e 73 75 6c 74 61 6e 74 73 2e 63 61 } //1 http://padgettconsultants.ca
		$a_00_6 = {55 52 4c 44 6f } //2 URLDo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2) >=3
 
}