
rule Trojan_Win64_Sirefef_X{
	meta:
		description = "Trojan:Win64/Sirefef.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 1e 4c 8d 45 00 48 8d 15 ?? ?? ?? ?? 8b cf ff d6 4c 8d 45 00 48 8d 15 ?? ?? ?? ?? 8b cf ff d6 48 8b 4d 08 } //1
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 5c 00 47 00 41 00 43 00 5f 00 33 00 32 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 } //1 \systemroot\assembly\GAC_32\Desktop.ini
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_X_2{
	meta:
		description = "Trojan:Win64/Sirefef.X,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 1e 4c 8d 45 00 48 8d 15 ?? ?? ?? ?? 8b cf ff d6 4c 8d 45 00 48 8d 15 ?? ?? ?? ?? 8b cf ff d6 48 8b 4d 08 } //1
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 5c 00 47 00 41 00 43 00 5f 00 33 00 32 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 } //1 \systemroot\assembly\GAC_32\Desktop.ini
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}