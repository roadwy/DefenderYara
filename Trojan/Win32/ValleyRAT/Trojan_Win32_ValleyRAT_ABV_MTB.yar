
rule Trojan_Win32_ValleyRAT_ABV_MTB{
	meta:
		description = "Trojan:Win32/ValleyRAT.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 31 30 33 2e 31 32 31 2e 39 33 2e 37 38 3a 32 33 32 33 2f [0-0f] 2e 62 69 6e } //5
		$a_80_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 25 73 22 20 2f 74 72 20 22 22 25 73 22 22 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 } //schtasks /create /tn "%s" /tr ""%s"" /sc onlogon /rl highest  1
		$a_80_2 = {43 72 65 61 74 65 50 65 72 73 69 73 74 65 6e 74 54 61 73 6b 20 63 61 6c 6c 65 64 } //CreatePersistentTask called  1
		$a_80_3 = {43 6c 65 61 6e 69 6e 67 20 75 70 20 6d 65 6d 6f 72 79 } //Cleaning up memory  1
		$a_80_4 = {44 65 6c 61 79 69 6e 67 20 65 78 65 63 75 74 69 6f 6e } //Delaying execution  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=9
 
}