
rule Backdoor_Linux_Mirai_KM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 00 00 02 7c 00 00 26 74 09 10 00 7c 7f 1b 78 41 a2 00 10 48 00 05 a9 93 e3 00 00 3b e0 ff ff } //1
		$a_01_1 = {80 1f 00 00 7f 84 00 00 40 bc 00 14 80 7f 00 04 4b ff ff c1 90 7f 00 04 48 00 00 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Backdoor_Linux_Mirai_KM_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.KM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 6a 6d 18 02 43 52 52 4e 47 56 02 4c 4d 56 02 44 4d 57 4c 46 22 00 40 43 4a 22 00 47 4c 43 40 4e 47 22 00 51 5b 51 56 47 4f 22 00 51 4a 22 00 0d 40 4b 4c 0d 40 57 51 5b 40 4d 5a 02 6f 6b 70 63 6b 22 00 6f 6b 70 63 6b 18 02 43 52 52 4e 47 56 02 4c 4d 56 02 44 4d 57 4c 46 22 00 0d 40 4b 4c 0d 40 57 51 5b 40 4d 5a 02 52 51 22 00 0d 40 4b 4c 0d 40 57 51 5b 40 4d 5a 02 49 4b 4e 4e 02 0f 1b 02 22 00 4e 4b 4c 57 5a } //1 橡ᡭ䌂剒䝎ɖ䵌ɖ䵄䱗≆䀀䩃"䱇䁃䝎"孑噑佇"䩑"䀍䱋䀍兗䁛婍漂火正"歯捰ᡫ䌂剒䝎ɖ䵌ɖ䵄䱗≆ഀ䭀ൌ址孑䵀ɚ兒"䀍䱋䀍兗䁛婍䤂之Ɏᬏ∂一䱋婗
		$a_01_1 = {4b 4c 46 4d 55 51 02 6c 76 02 14 0c 13 19 02 75 6d 75 14 16 0b 02 63 52 52 4e 47 75 47 40 69 4b 56 0d 17 11 15 0c 11 14 02 0a 69 6a 76 6f 6e 0e 02 4e 4b 49 47 02 65 47 41 49 4d 0b 02 61 4a 50 4d 4f 47 0d 17 13 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}