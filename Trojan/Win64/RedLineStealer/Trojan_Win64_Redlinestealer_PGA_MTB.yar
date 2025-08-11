
rule Trojan_Win64_Redlinestealer_PGA_MTB{
	meta:
		description = "Trojan:Win64/Redlinestealer.PGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {31 38 35 2e 38 31 2e 36 38 2e 31 34 37 2f 62 69 6e 2f 62 6f 74 36 34 2e 62 69 6e } //185.81.68.147/bin/bot64.bin  1
		$a_80_1 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 74 61 72 74 75 70 41 70 70 72 6f 76 65 64 5c 52 75 6e } //CurrentVersion\Explorer\StartupApproved\Run  1
		$a_01_2 = {62 69 74 63 6f 69 6e 63 61 73 68 } //1 bitcoincash
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}