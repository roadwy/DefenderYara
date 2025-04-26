
rule Trojan_BAT_Barys_GJI_MTB{
	meta:
		description = "Trojan:BAT/Barys.GJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {61 48 52 30 63 48 4d 36 4c 79 39 68 64 58 52 6f 4c 6e 56 75 61 32 35 76 64 32 35 77 4c 6d 39 75 5a 53 38 2f 5a 32 46 74 5a 57 68 6c 62 48 42 6c 63 6e 4d 3d } //aHR0cHM6Ly9hdXRoLnVua25vd25wLm9uZS8/Z2FtZWhlbHBlcnM=  1
		$a_80_1 = {52 6d 39 79 59 32 56 56 63 47 52 68 64 47 56 47 63 6d 39 74 54 56 55 3d } //Rm9yY2VVcGRhdGVGcm9tTVU=  1
		$a_80_2 = {64 32 52 6d 61 57 78 30 5a 58 49 3d } //d2RmaWx0ZXI=  1
		$a_80_3 = {57 47 4a 73 52 32 46 74 5a 56 4e 68 64 6d 55 3d } //WGJsR2FtZVNhdmU=  1
		$a_80_4 = {64 65 6c 20 2f 73 20 2f 66 20 2f 71 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 50 72 65 66 65 74 63 68 } //del /s /f /q C:\Windows\Prefetch  1
		$a_80_5 = {43 3a 5c 70 6b 65 79 } //C:\pkey  1
		$a_80_6 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  1
		$a_80_7 = {59 4f 55 52 20 41 4e 54 49 56 49 52 55 53 20 49 53 20 42 4c 4f 43 4b 49 4e 47 20 54 48 45 20 4c 4f 41 44 45 52 } //YOUR ANTIVIRUS IS BLOCKING THE LOADER  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}