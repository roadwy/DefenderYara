
rule Trojan_Win64_Androm_ABN_MTB{
	meta:
		description = "Trojan:Win64/Androm.ABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {2f 00 2f 00 32 00 30 00 36 00 2e 00 31 00 31 00 39 00 2e 00 31 00 39 00 31 00 2e 00 31 00 30 00 36 00 2f 00 [0-0f] 2e 00 62 00 69 00 6e 00 } //5
		$a_03_1 = {2f 00 2f 00 79 00 7a 00 67 00 79 00 32 00 2e 00 63 00 63 00 2f 00 [0-0f] 2e 00 62 00 69 00 6e 00 } //5
		$a_80_2 = {5c 4a 48 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e } //\JH.exe /create /sc onlogon  1
		$a_80_3 = {5c 55 73 5c 57 69 6e 2e 65 78 65 } //\Us\Win.exe  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=12
 
}