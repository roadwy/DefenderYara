
rule PWS_Win32_Frethog_BU{
	meta:
		description = "PWS:Win32/Frethog.BU,SIGNATURE_TYPE_PEHSTR,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 5c } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad\
		$a_01_1 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 } //10 regsvr32.exe /s 
		$a_01_2 = {25 73 26 4e 61 6d 65 3d 25 73 26 50 61 73 73 3d 25 73 26 72 6f 6c 65 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 25 73 } //1 %s&Name=%s&Pass=%s&role=%s&Level=%s&Money=%s
		$a_01_3 = {3d 25 73 26 50 61 73 73 52 6f 6c 65 3d 25 73 26 4d 42 3d 25 73 26 43 61 72 64 3d 25 73 3d 25 73 7c 25 73 3d 25 73 7c 25 73 3d 25 73 26 53 74 6f 72 65 3d 25 73 26 4b 65 79 3d 25 73 26 } //1 =%s&PassRole=%s&MB=%s&Card=%s=%s|%s=%s|%s=%s&Store=%s&Key=%s&
		$a_01_4 = {3f 61 63 74 69 6f 6e 3d 67 65 74 70 6f 73 26 4e 61 6d 65 3d } //1 ?action=getpos&Name=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=22
 
}