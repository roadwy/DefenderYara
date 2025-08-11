
rule Ransom_Win64_FileCoder_GXD_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.GXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 4c 4c 20 59 4f 55 52 20 49 4d 50 4f 52 54 41 4e 54 20 46 49 4c 45 53 20 41 52 45 20 53 54 4f 4c 45 4e 20 41 4e 44 20 45 4e 43 52 59 50 54 45 44 } //1 ALL YOUR IMPORTANT FILES ARE STOLEN AND ENCRYPTED
		$a_80_1 = {2f 63 20 53 43 48 54 41 53 4b 53 2e 65 78 65 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 22 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 41 4c 50 48 56 22 20 2f 46 } ///c SCHTASKS.exe /Delete /TN "Windows Update ALPHV" /F  1
		$a_01_2 = {43 6f 6e 74 61 63 74 20 75 73 20 69 6d 6d 65 64 69 61 74 65 6c 79 20 74 6f 20 70 72 65 76 65 6e 74 20 64 61 74 61 20 6c 65 61 6b 61 67 65 20 61 6e 64 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 } //1 Contact us immediately to prevent data leakage and recover your files
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}