
rule TrojanDropper_O97M_Powdow_RSD_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.RSD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 65 70 20 62 79 70 61 73 73 20 2d 6e 6f 6e 69 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 65 6e 63 } //1 powershell.exe -ep bypass -noni -nop -w hidden -enc
		$a_01_1 = {6f 41 43 63 41 61 41 42 30 41 48 51 41 63 41 42 7a 41 44 6f 41 4c 77 41 76 41 48 49 41 59 51 42 33 41 43 34 41 5a 77 42 70 41 48 51 41 61 41 42 31 41 47 49 41 64 51 42 7a 41 47 55 41 63 67 42 6a 41 47 38 41 62 67 42 30 41 47 55 41 62 67 42 30 41 43 34 41 59 77 42 76 41 47 30 41 4c 77 42 6a 41 48 49 41 59 51 42 36 41 48 6b 41 63 67 42 76 41 47 4d 41 61 77 42 70 41 47 34 41 63 77 42 31 41 48 4d 41 61 41 42 70 41 43 38 41 55 41 42 76 41 45 4d 41 4c 77 42 74 41 47 45 41 63 77 42 30 41 47 55 41 63 67 41 76 41 48 41 41 62 77 42 6a 41 43 34 41 63 41 42 7a 41 44 45 41 50 77 41 6e 41 43 6b 41 } //1 oACcAaAB0AHQAcABzADoALwAvAHIAYQB3AC4AZwBpAHQAaAB1AGIAdQBzAGUAcgBjAG8AbgB0AGUAbgB0AC4AYwBvAG0ALwBjAHIAYQB6AHkAcgBvAGMAawBpAG4AcwB1AHMAaABpAC8AUABvAEMALwBtAGEAcwB0AGUAcgAvAHAAbwBjAC4AcABzADEAPwAnACkA
		$a_01_2 = {53 68 65 6c 6c 20 63 6d 64 2c 20 30 } //1 Shell cmd, 0
		$a_01_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}