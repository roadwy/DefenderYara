
rule Trojan_Win64_CryptoClipper_A_MTB{
	meta:
		description = "Trojan:Win64/CryptoClipper.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 6f 2d 63 6c 69 70 70 65 72 2f 6d 61 69 6e 2e 67 6f } //2 crypto-clipper/main.go
		$a_01_1 = {63 6c 69 70 62 6f 61 72 64 2e 67 6f } //2 clipboard.go
		$a_01_2 = {63 6c 69 70 62 6f 61 72 64 5f 77 69 6e 64 6f 77 73 2e 67 6f } //2 clipboard_windows.go
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}