
rule Trojan_Win64_IcedID_MAH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {44 32 36 6f 45 6e } //1 D26oEn
		$a_01_1 = {47 4e 65 73 56 6b 4f 49 64 52 } //1 GNesVkOIdR
		$a_01_2 = {47 64 57 49 39 69 34 } //1 GdWI9i4
		$a_01_3 = {48 79 75 61 73 62 62 6a 68 61 73 } //1 Hyuasbbjhas
		$a_01_4 = {49 41 39 69 46 4d 6c } //1 IA9iFMl
		$a_01_5 = {49 49 53 39 56 4d 46 46 55 68 } //1 IIS9VMFFUh
		$a_01_6 = {49 6c 66 39 64 6c 32 43 } //1 Ilf9dl2C
		$a_01_7 = {4e 4c 34 44 74 38 49 79 61 } //1 NL4Dt8Iya
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}