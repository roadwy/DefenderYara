
rule Ransom_Win32_NefiCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/NefiCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 42 66 55 76 6e 54 4d 36 46 46 59 48 33 57 53 76 69 30 44 53 2f 6d 47 4f 32 61 79 36 76 79 6f 47 6b 46 77 64 77 51 61 54 44 2f 65 78 58 6e 2d 46 5a 33 48 7a 52 32 6a 56 54 70 69 4c 42 75 2f 33 34 6c 43 50 52 4f 41 39 76 68 32 41 5a 6b 5a 62 67 43 55 } //5 Go build ID: "BfUvnTM6FFYH3WSvi0DS/mGO2ay6vyoGkFwdwQaTD/exXn-FZ3HzR2jVTpiLBu/34lCPROA9vh2AZkZbgCU
		$a_01_1 = {5c 52 45 41 44 4d 45 2e 68 74 6d 6c 5f } //1 \README.html_
		$a_01_2 = {64 6f 6e 27 74 20 72 65 6e 61 6d 65 20 79 6f 75 72 20 66 69 6c 65 } //1 don't rename your file
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}