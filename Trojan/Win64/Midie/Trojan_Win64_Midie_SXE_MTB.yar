
rule Trojan_Win64_Midie_SXE_MTB{
	meta:
		description = "Trojan:Win64/Midie.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 08 00 00 "
		
	strings :
		$a_80_0 = {5b 2b 5d 20 49 6e 6a 65 63 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 } //[+] Injection Complete  30
		$a_80_1 = {5b 69 5d 20 43 72 65 64 69 74 20 43 61 72 64 73 } //[i] Credit Cards  10
		$a_80_2 = {5b 2b 5d 20 43 72 65 61 74 65 64 20 43 68 72 6f 6d 65 2e 65 78 65 20 50 72 6f 63 65 73 73 } //[+] Created Chrome.exe Process  10
		$a_80_3 = {5b 69 5d 20 48 69 73 74 6f 72 79 } //[i] History  1
		$a_80_4 = {5b 69 5d 20 43 6f 6f 6b 69 65 73 } //[i] Cookies  1
		$a_80_5 = {5b 69 5d 20 41 75 74 6f 66 69 6c 6c } //[i] Autofill  1
		$a_80_6 = {5b 69 5d 20 54 6f 6b 65 6e 73 } //[i] Tokens  1
		$a_80_7 = {5b 2b 5d 20 45 78 74 72 61 63 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 } //[+] Extraction Complete  1
	condition:
		((#a_80_0  & 1)*30+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=45
 
}