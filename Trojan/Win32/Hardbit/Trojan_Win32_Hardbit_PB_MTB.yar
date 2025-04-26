
rule Trojan_Win32_Hardbit_PB_MTB{
	meta:
		description = "Trojan:Win32/Hardbit.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 README.txt
		$a_01_1 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 53 54 4f 4c 45 4e 20 41 4e 44 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILES ARE STOLEN AND ENCRYPTED
		$a_01_2 = {70 75 72 63 68 61 73 65 20 6f 66 20 61 20 70 72 69 76 61 74 65 20 6b 65 79 } //1 purchase of a private key
		$a_01_3 = {72 65 6e 61 6d 65 20 6f 72 20 6d 6f 64 69 66 79 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 rename or modify encrypted files
		$a_01_4 = {70 61 79 20 72 61 6e 73 6f 6d } //1 pay ransom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}