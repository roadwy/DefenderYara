
rule Trojan_Win64_Coinstealer_PAGF_MTB{
	meta:
		description = "Trojan:Win64/Coinstealer.PAGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 48 49 54 20 57 41 4c 4c 45 54 20 41 44 44 52 45 53 53 45 53 3a } //2 SHIT WALLET ADDRESSES:
		$a_01_1 = {22 64 61 74 61 22 3a 7b 22 61 64 64 72 65 73 73 22 3a 22 } //1 "data":{"address":"
		$a_01_2 = {2f 00 46 00 69 00 6c 00 65 00 73 00 2f 00 4c 00 6f 00 67 00 69 00 6e 00 2e 00 70 00 68 00 70 00 } //2 /Files/Login.php
		$a_01_3 = {26 74 72 75 73 74 77 61 6c 6c 65 74 46 69 6c 65 3d } //1 &trustwalletFile=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=6
 
}