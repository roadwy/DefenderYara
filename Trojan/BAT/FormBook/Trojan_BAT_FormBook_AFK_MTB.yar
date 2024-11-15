
rule Trojan_BAT_FormBook_AFK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 03 91 1d 59 1f 09 59 d2 25 0a 9c 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_FormBook_AFK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 0d 00 06 28 ?? ?? ?? 06 00 00 06 17 58 0a 06 7e 08 00 00 04 8e 69 fe 04 0b 07 2d e5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFK_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 1c 02 06 03 16 16 28 07 00 00 06 16 31 01 2a 20 e9 04 00 00 28 0d 00 00 0a 07 17 58 0b 07 1a 32 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_FormBook_AFK_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 13 39 2b 2c 11 04 11 39 11 04 11 39 91 09 11 37 91 11 39 1a 5d 1d 5f 62 d2 61 11 04 11 39 17 da 91 61 20 00 01 00 00 5d b4 9c 11 39 17 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFK_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 2b 28 0a 2b f1 0b 2b f8 02 50 06 91 19 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFK_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 11 0f 11 13 95 58 20 ff 00 00 00 5f 13 2f 11 10 13 30 07 11 30 91 13 31 11 0f 11 2f 95 13 32 11 31 11 32 61 13 33 11 0e 11 30 11 33 d2 9c 11 10 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFK_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 5a 58 11 11 07 6f ?? 00 00 0a 5a 58 13 0a 11 0c 11 05 11 0a 91 58 13 0c 11 0d 11 05 11 0a 17 58 91 58 13 0d 11 0e 11 05 11 0a 18 58 91 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_FormBook_AFK_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 } //2
		$a_01_1 = {4d 61 69 6e 53 74 6f 72 65 46 75 6e 63 74 69 6f 6e 61 6c 69 74 79 2e 4d 6f 64 65 6c 73 } //1 MainStoreFunctionality.Models
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFK_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 ?? 00 00 06 d2 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 06 d2 59 20 00 01 00 00 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFK_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 8e 69 5d 09 8e 69 58 13 10 11 10 09 8e 69 5d 13 11 09 11 11 91 13 12 11 0f 17 58 08 5d 13 13 11 13 08 58 13 14 11 14 08 5d 13 15 11 15 08 5d 08 58 } //2
		$a_01_1 = {4b 65 6c 6c 65 72 6d 61 6e 53 6f 66 74 77 61 72 65 } //1 KellermanSoftware
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFK_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0f 2b 5a 00 11 07 17 58 20 ff 00 00 00 5f 13 07 11 05 11 04 11 07 95 58 20 ff 00 00 00 5f 13 05 11 04 11 07 95 13 06 11 04 11 07 11 04 11 05 95 9e 11 04 11 05 11 06 9e 09 11 0f 07 11 0f 91 11 04 11 04 11 07 95 11 04 11 05 95 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFK_MTB_12{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 13 04 16 13 05 2b 3c 11 04 11 05 9a 0c 08 6f ?? 00 00 0a 04 28 ?? 00 00 0a 2c 22 72 ?? 00 00 70 08 72 ?? 00 00 70 18 8d ?? 00 00 01 13 06 11 06 16 03 a2 11 06 28 ?? 00 00 06 0d de 10 11 05 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFK_MTB_13{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 60 16 0d 2b 4f 07 08 09 6f 55 00 00 0a 13 09 06 12 09 28 56 00 00 0a 6f 57 00 00 0a 06 6f 58 00 00 0a 20 00 b8 00 00 2f 0d 06 12 09 28 59 00 00 0a 6f 57 00 00 0a 06 6f 58 00 00 0a 20 00 b8 00 00 2f 0d 06 12 09 28 5a 00 00 0a 6f 57 00 00 0a 09 17 58 0d 09 07 6f 5b 00 00 0a 32 a8 08 17 58 0c 08 07 6f 5c 00 00 0a 32 97 07 6f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_FormBook_AFK_MTB_14{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {37 64 62 65 64 61 63 65 2d 36 33 38 32 2d 34 61 63 30 2d 61 37 38 37 2d 30 66 35 37 38 63 66 30 65 63 30 34 } //1 7dbedace-6382-4ac0-a787-0f578cf0ec04
		$a_01_1 = {44 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 20 00 49 00 6d 00 61 00 67 00 65 00 20 00 41 00 64 00 64 00 2d 00 32 00 57 00 41 00 59 00 53 00 } //1 Database Image Add-2WAYS
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 get_ResourceManager
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_BAT_FormBook_AFK_MTB_15{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 09 11 0a 9a 13 0b 00 06 02 11 0b 6f 1f 00 00 0a 28 04 00 00 06 58 0a 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d9 } //2
		$a_01_1 = {38 31 36 66 63 30 34 31 2d 33 31 35 39 2d 34 32 30 34 2d 61 39 65 36 2d 66 36 63 30 34 38 64 36 31 62 31 30 } //1 816fc041-3159-4204-a9e6-f6c048d61b10
		$a_01_2 = {4d 00 65 00 72 00 67 00 69 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Mergin.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_FormBook_AFK_MTB_16{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 2e 11 05 11 06 9a 13 07 00 11 04 6f ?? 01 00 0a 11 07 28 ?? 00 00 0a 13 08 11 08 2c 0b 00 06 07 11 04 a2 07 17 58 } //1
		$a_03_1 = {0d 2b 48 00 06 09 06 8e 69 5d 06 09 06 8e 69 5d 91 07 09 07 6f ?? 01 00 0a 5d 6f ?? 02 00 0a 61 28 ?? 00 00 0a 06 09 17 58 06 8e 69 5d 91 28 ?? 02 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 02 00 0a 9c 00 09 15 58 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_AFK_MTB_17{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 2d 50 72 6f 6a 65 63 74 2d 70 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 4d 69 4e 6c 49 6c 2e 70 64 62 } //1 p-Project-p\obj\x86\Debug\MiNlIl.pdb
		$a_01_1 = {6b 00 6f 00 74 00 68 00 61 00 72 00 69 00 71 00 68 00 79 00 74 00 6f 00 2e 00 63 00 6f 00 6d 00 } //2 kothariqhyto.com
		$a_01_2 = {34 39 36 62 61 37 37 63 2d 39 38 34 33 2d 34 63 61 34 2d 61 63 30 64 2d 33 35 32 35 30 66 62 61 63 31 65 39 } //1 496ba77c-9843-4ca4-ac0d-35250fbac1e9
		$a_01_3 = {4d 69 4e 6c 49 6c 2e 6c 6f 67 6f 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 MiNlIl.logon.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_AFK_MTB_18{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 16 ac 01 00 13 04 2b 19 00 06 11 04 06 8e 69 5d 02 06 11 04 28 ?? ?? ?? 06 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d d9 } //2
		$a_01_1 = {55 00 6e 00 63 00 6c 00 65 00 4e 00 61 00 62 00 65 00 65 00 6c 00 73 00 42 00 61 00 6b 00 65 00 72 00 79 00 } //1 UncleNabeelsBakery
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 System.Reflection.Assembly
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_FormBook_AFK_MTB_19{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 09 6f ?? ?? ?? 0a 13 0b 16 13 0c 11 05 11 08 9a 72 55 04 00 70 28 ?? ?? ?? 0a 13 0d 11 0d 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 42 11 05 11 08 9a 72 59 04 00 70 28 ?? ?? ?? 0a 13 0e 11 0e 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 20 11 05 11 08 9a 72 5d 04 00 70 28 ?? ?? ?? 0a 13 0f 11 0f 2c 0b 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 07 11 0c } //2
		$a_01_1 = {43 00 53 00 44 00 4c 00 5f 00 51 00 4c 00 4e 00 53 00 5f 00 51 00 4c 00 4c 00 55 00 4f 00 4e 00 47 00 } //1 CSDL_QLNS_QLLUONG
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}