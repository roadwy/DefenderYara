
rule Trojan_BAT_Disco_GFM_MTB{
	meta:
		description = "Trojan:BAT/Disco.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //cdn.discordapp.com/attachments  1
		$a_80_1 = {5a 65 75 73 2e 65 78 65 } //Zeus.exe  1
		$a_80_2 = {61 70 69 2e 66 33 64 2e 61 74 2f 76 31 2f 6f 62 66 75 73 63 61 74 65 2e 70 68 70 3f 6b 65 79 3d } //api.f3d.at/v1/obfuscate.php?key=  1
		$a_01_3 = {4c 50 51 64 56 73 37 43 39 6a 67 53 4b 48 68 64 6f 43 } //1 LPQdVs7C9jgSKHhdoC
		$a_80_4 = {4f 4f 6d 55 73 6b 32 54 54 61 6d 32 75 45 30 53 5a 32 2e 77 4d 4a 56 67 75 6d 73 66 32 44 43 66 71 6c 61 4b 71 } //OOmUsk2TTam2uE0SZ2.wMJVgumsf2DCfqlaKq  1
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_80_7 = {66 75 72 6b 69 73 67 61 79 } //furkisgay  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}