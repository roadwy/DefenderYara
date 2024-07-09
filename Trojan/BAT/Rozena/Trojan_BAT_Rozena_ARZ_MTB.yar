
rule Trojan_BAT_Rozena_ARZ_MTB{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 0a 28 01 00 00 0a 16 9a 28 02 00 00 0a 06 28 03 00 00 0a 39 00 00 00 00 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 16 2b 15 07 11 16 07 11 16 91 20 fa 00 00 00 61 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 e4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_3{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 13 06 2b 18 07 11 06 07 11 06 91 1f 22 61 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_4{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 06 16 08 07 28 ?? ?? ?? 0a 7e 02 00 00 0a 16 08 7e 02 00 00 0a 16 7e 02 00 00 0a 28 ?? ?? ?? 06 0d 09 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_5{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 16 08 6e 28 ?? ?? ?? 0a 07 8e 69 28 ?? ?? ?? 0a 00 7e 0c 00 00 0a 0d 16 13 04 7e 0c 00 00 0a 13 05 16 16 08 11 05 16 12 04 28 ?? ?? ?? 06 0d 09 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_6{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 08 8e 69 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 0d 08 16 09 6e 28 ?? 00 00 0a 08 8e 69 28 ?? 00 00 0a 16 16 09 07 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_7{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 14 07 11 07 8f ?? 00 00 01 25 47 08 61 d2 52 11 07 17 58 13 07 11 07 07 8e 69 32 e5 } //2
		$a_01_1 = {44 65 73 6b 74 6f 70 5c 63 6f 64 65 5c 45 6e 63 72 79 70 74 69 6f 6e 5c 45 6e 63 72 79 70 74 69 6f 6e 5c 6f 62 6a 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 45 6e 63 72 79 70 74 69 6f 6e 2e 70 64 62 } //1 Desktop\code\Encryption\Encryption\obj\x64\Release\Encryption.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Rozena_ARZ_MTB_8{
	meta:
		description = "Trojan:BAT/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 8d 15 00 00 01 0b 16 0c 2b 0f 07 08 06 08 93 28 ?? ?? ?? 0a 9c 08 17 58 0c 08 07 8e 69 32 eb } //2
		$a_01_1 = {6e 00 69 00 65 00 74 00 76 00 35 00 36 00 37 00 } //1 nietv567
		$a_01_2 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4c 00 6f 00 79 00 65 00 69 00 6e 00 44 00 42 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 41 00 50 00 49 00 } //1 HKEY_CURRENT_USER\Software\LoyeinDBServiceAPI
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}