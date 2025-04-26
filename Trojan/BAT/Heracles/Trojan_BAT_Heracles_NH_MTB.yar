
rule Trojan_BAT_Heracles_NH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 06 08 06 93 02 7b ?? 01 00 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Heracles_NH_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 11 04 08 59 0d 02 7b 61 00 00 04 09 0e 04 0e 05 08 28 bb 00 00 0a 08 2a } //3
		$a_01_1 = {4a 48 4f 4e 4e 45 54 20 53 55 50 52 45 4d 45 } //1 JHONNET SUPREME
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_BAT_Heracles_NH_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 03 0c 2b f5 2a 06 6f ?? ?? 00 06 28 ?? ?? 00 0a 28 ?? ?? 00 0a 2a } //5
		$a_01_1 = {4e 6a 72 67 61 6f 73 68 78 78 6f 6f 69 6b 73 72 67 78 74 } //1 Njrgaoshxxooiksrgxt
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Heracles_NH_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 43 6b 72 4a 72 75 59 57 47 73 49 45 4a 4d 46 57 78 52 63 6d } //2 lCkrJruYWGsIEJMFWxRcm
		$a_01_1 = {46 4e 44 4f 4a 62 74 73 58 71 65 54 58 6e 78 74 } //2 FNDOJbtsXqeTXnxt
		$a_01_2 = {54 65 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 31 } //2 Test.Properties.Resource1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_BAT_Heracles_NH_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b 1f 09 11 07 9a 08 28 24 00 00 0a 2c 0d 09 11 07 17 58 9a 13 04 16 } //7
		$a_81_1 = {61 73 70 6e 65 74 5f 77 70 2e 65 78 65 } //1 aspnet_wp.exe
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
	condition:
		((#a_01_0  & 1)*7+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=10
 
}
rule Trojan_BAT_Heracles_NH_MTB_6{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 d2 00 00 06 6f 89 01 00 0a 0d 28 cd 00 00 06 13 04 11 04 39 30 00 00 00 11 04 6f 15 00 00 0a 16 3e 23 00 00 00 11 04 20 40 0f 00 00 28 6d 00 00 06 } //2
		$a_01_1 = {28 7a 01 00 0a 11 04 6f 89 01 00 0a 0d 04 8e 69 28 c6 01 00 0a 13 05 1f 0e 09 8e 69 58 04 8e 69 58 8d a9 00 00 01 13 06 11 06 16 16 9c 07 16 11 06 17 1e 28 60 01 00 0a 11 06 1f 09 09 8e } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}
rule Trojan_BAT_Heracles_NH_MTB_7{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 0f 04 00 06 06 20 ?? ?? ?? 35 60 0a 6f ?? ?? ?? 0a 20 ?? ?? ?? 4e 06 44 ?? ?? ?? ff 02 20 ?? ?? ?? 3b 06 60 ?? ?? ?? 00 00 04 06 20 ?? ?? ?? 3f 61 20 ?? ?? ?? 4d 06 5f 0a 02 fe ?? ?? ?? ?? 06 06 20 ?? ?? ?? 00 62 0a 73 ?? ?? ?? 06 20 ?? ?? ?? 18 06 60 0a 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 06 20 ?? ?? ?? 18 61 20 ?? ?? ?? 3e 06 5e 0a 02 20 ?? ?? ?? 45 06 20 ?? ?? ?? 00 5f 62 0a } //5
		$a_01_1 = {47 48 4c 2e 65 78 65 } //1 GHL.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Heracles_NH_MTB_8{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 06 04 11 07 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 13 08 12 08 28 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 13 06 11 07 17 58 13 07 11 07 04 6f ?? ?? 00 0a fe 04 13 09 11 09 2d c4 } //5
		$a_03_1 = {28 aa 01 00 0a 0a 06 18 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 72 ?? ?? ?? 70 a2 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b } //5
		$a_01_2 = {76 00 53 00 53 00 31 00 34 00 6c 00 70 00 57 00 4e 00 6b 00 44 00 43 00 59 00 4c 00 33 00 65 00 45 00 46 00 4f 00 47 00 77 00 45 00 3d 00 } //1 vSS14lpWNkDCYL3eEFOGwE=
		$a_01_3 = {4c 00 36 00 6a 00 30 00 47 00 4d 00 49 00 78 00 4f 00 36 00 43 00 53 00 58 00 4c 00 48 00 73 00 66 00 30 00 37 00 30 00 62 00 } //1 L6j0GMIxO6CSXLHsf070b
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}