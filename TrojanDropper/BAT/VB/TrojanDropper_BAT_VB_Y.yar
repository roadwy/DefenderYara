
rule TrojanDropper_BAT_VB_Y{
	meta:
		description = "TrojanDropper:BAT/VB.Y,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 4f 4e 53 44 4b 52 68 49 49 58 4e 51 49 67 4b 6f 6d 55 4a } //3 OONSDKRhIIXNQIgKomUJ
		$a_01_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //2 C:\Windows\Microsoft.NET\Framework\v2.0.50727\vbc.exe
		$a_01_2 = {55 00 6d 00 56 00 68 00 5a 00 46 00 42 00 79 00 62 00 32 00 4e 00 6c 00 63 00 33 00 4e 00 4e 00 5a 00 57 00 31 00 76 00 63 00 6e 00 6b 00 3d 00 } //3 UmVhZFByb2Nlc3NNZW1vcnk=
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=8
 
}