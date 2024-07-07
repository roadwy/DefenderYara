
rule Worm_Win32_Nachi{
	meta:
		description = "Worm:Win32/Nachi,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 5c 7b 45 36 46 42 35 45 32 30 2d 44 45 33 35 2d 31 31 43 46 2d 39 43 38 37 2d 30 30 41 41 30 30 35 31 32 37 45 44 7d 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 CLSID\{E6FB5E20-DE35-11CF-9C87-00AA005127ED}\InProcServer32
		$a_01_1 = {57 33 53 56 43 5c 50 61 72 61 6d 65 74 65 72 73 5c 56 69 72 74 75 61 6c 20 52 6f 6f 74 73 } //2 W3SVC\Parameters\Virtual Roots
		$a_01_2 = {25 73 20 2f 71 75 69 65 74 20 2f 6e 6f 72 65 73 74 61 72 74 20 2f 6f 20 2f 6e } //1 %s /quiet /norestart /o /n
		$a_01_3 = {57 69 6e 64 6f 77 73 32 30 30 30 2d 4b 42 38 32 38 37 34 39 2d 78 38 36 2d 45 4e 55 2e 65 78 65 } //1 Windows2000-KB828749-x86-ENU.exe
		$a_01_4 = {25 73 5c 64 72 69 76 65 72 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 %s\drivers\svchost.exe
		$a_01_5 = {53 65 6c 65 63 74 20 22 44 41 56 3a 64 69 73 70 6c 61 79 6e 61 6d 65 22 20 66 72 6f 6d 20 73 63 6f 70 65 28 29 } //1 Select "DAV:displayname" from scope()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}