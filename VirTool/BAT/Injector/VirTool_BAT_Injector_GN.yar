
rule VirTool_BAT_Injector_GN{
	meta:
		description = "VirTool:BAT/Injector.GN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 2c 20 53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2c 20 56 65 72 73 69 6f 6e 3d 34 2e 30 2e 30 2e 30 2c 20 43 75 6c 74 75 72 65 3d 6e 65 75 74 72 61 6c 2c 20 50 75 62 6c 69 63 4b 65 79 54 6f 6b 65 6e 3d 62 30 33 66 35 66 37 66 31 31 64 35 30 61 33 61 50 41 44 50 41 44 } //1 hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD
		$a_01_1 = {61 00 4a 00 4b 00 30 00 66 00 49 00 38 00 4e 00 } //1 aJK0fI8N
		$a_01_2 = {61 00 55 00 54 00 4f 00 55 00 4d 00 36 00 4e 00 61 00 63 00 48 00 35 00 } //1 aUTOUM6NacH5
		$a_01_3 = {61 00 59 00 64 00 42 00 72 00 49 00 76 00 50 00 4e 00 73 00 } //1 aYdBrIvPNs
		$a_01_4 = {61 00 7a 00 62 00 37 00 49 00 55 00 58 00 7a 00 32 00 61 00 51 00 61 00 } //1 azb7IUXz2aQa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}