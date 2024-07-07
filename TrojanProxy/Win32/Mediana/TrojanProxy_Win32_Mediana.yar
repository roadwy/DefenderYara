
rule TrojanProxy_Win32_Mediana{
	meta:
		description = "TrojanProxy:Win32/Mediana,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 50 61 67 65 20 69 73 20 45 73 74 61 62 6c 69 73 68 69 6e 67 2e 2e 2e } //4 This Page is Establishing...
		$a_01_1 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 69 6e 64 65 78 2e 63 67 69 3f 25 73 26 25 73 20 48 54 54 50 2f 31 2e 30 } //4 POST http://%s:%d/index.cgi?%s&%s HTTP/1.0
		$a_01_2 = {43 52 53 45 52 56 45 52 5f 4d 55 54 45 58 5f 4f 4e 43 45 } //2 CRSERVER_MUTEX_ONCE
		$a_01_3 = {78 2d 77 61 76 2f 79 2d 69 6d 67 } //2 x-wav/y-img
		$a_01_4 = {5c 6d 73 65 78 74 6c 6f 67 2e 64 6c 6c } //2 \msextlog.dll
		$a_00_5 = {3c 2e 75 15 80 7c 31 01 45 75 0e 80 7c 31 02 58 75 07 80 7c 31 03 45 74 08 } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_00_5  & 1)*2) >=12
 
}