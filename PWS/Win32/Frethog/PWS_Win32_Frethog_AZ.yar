
rule PWS_Win32_Frethog_AZ{
	meta:
		description = "PWS:Win32/Frethog.AZ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 67 6f 6c 64 70 61 73 73 3d 00 00 26 73 61 76 65 70 61 73 73 3d 00 00 26 73 61 76 69 6e 67 73 3d 00 00 00 26 6d 6f 6e 65 79 3d 00 26 6c 65 76 65 6c 3d 00 } //1
		$a_01_1 = {67 61 6d 65 63 6c 69 65 6e 74 2e 65 78 65 } //1 gameclient.exe
		$a_01_2 = {6c 69 6e 2e 61 73 70 00 75 70 66 69 6c 65 2e 61 73 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}