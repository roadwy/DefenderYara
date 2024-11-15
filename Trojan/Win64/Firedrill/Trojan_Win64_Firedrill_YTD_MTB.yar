
rule Trojan_Win64_Firedrill_YTD_MTB{
	meta:
		description = "Trojan:Win64/Firedrill.YTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 45 47 20 44 45 4c 45 54 45 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 56 } //1 REG DELETE HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V
		$a_81_1 = {46 49 52 45 44 52 49 4c 4c 20 2f 66 } //1 FIREDRILL /f
		$a_81_2 = {50 65 72 73 69 73 74 65 6e 63 65 20 54 65 73 74 20 42 69 6e 61 72 79 20 42 6c 6f 62 } //1 Persistence Test Binary Blob
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}