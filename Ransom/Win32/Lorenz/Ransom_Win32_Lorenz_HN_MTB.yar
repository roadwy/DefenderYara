
rule Ransom_Win32_Lorenz_HN_MTB{
	meta:
		description = "Ransom:Win32/Lorenz.HN!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 72 65 6e 7a 65 64 7a 79 7a 79 6a 68 7a 78 76 6c 63 76 33 34 37 6e } //1 lorenzedzyzyjhzxvlcv347n
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 64 6f 77 6e 6c 6f 61 64 65 64 2c 20 65 6e 63 72 79 70 74 65 64 2c 20 61 6e 64 20 63 75 72 72 65 6e 74 6c 79 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e 20 59 6f 75 20 63 61 6e 20 63 68 65 63 6b 20 69 74 } //1 Your files are downloaded, encrypted, and currently unavailable. You can check it
		$a_01_2 = {31 00 36 00 32 00 2e 00 33 00 33 00 2e 00 31 00 37 00 39 00 2e 00 34 00 35 00 } //1 162.33.179.45
		$a_01_3 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 } //1 -----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}