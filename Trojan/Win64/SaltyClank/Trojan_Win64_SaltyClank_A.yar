
rule Trojan_Win64_SaltyClank_A{
	meta:
		description = "Trojan:Win64/SaltyClank.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 75 6c 64 6e 27 74 20 65 78 74 72 61 63 74 20 6b 65 79 20 2d 20 63 6f 72 72 75 70 74 65 64 20 66 69 6c 65 3f 0a 00 } //1
		$a_01_1 = {49 6e 76 61 6c 69 64 20 61 72 67 75 6d 65 6e 74 2e 0a 00 } //1
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 65 3a 4f 4e 20 2f 76 3a 4f 46 46 20 2f 64 20 2f 63 } //1 cmd.exe /e:ON /v:OFF /d /c
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 6c 75 63 61 6b 5c 2e 63 61 72 67 6f } //1 C:\Users\lucak\.cargo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}