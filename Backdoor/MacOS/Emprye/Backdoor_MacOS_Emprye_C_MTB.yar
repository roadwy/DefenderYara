
rule Backdoor_MacOS_Emprye_C_MTB{
	meta:
		description = "Backdoor:MacOS/Emprye.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {55 48 89 e5 48 81 ec c0 04 00 00 31 ff 48 8d 35 d7 06 00 00 48 8d 05 45 02 00 00 b9 8b 04 00 00 89 ca 4c 8d 85 60 fb ff ff 4c 8b 0d 50 07 00 00 4d 8b 09 4c 89 4d f8 89 bd 5c fb ff ff 4c 89 c7 48 89 b5 50 fb ff ff 48 89 c6 e8 77 01 00 00 8b bd 5c fb ff ff 48 8b b5 50 fb ff ff e8 7d 01 00 00 48 89 85 48 fb ff ff e8 47 01 00 00 31 c9 89 ce 48 8d bd 60 fb ff ff e8 2b 01 00 00 89 85 44 fb ff ff e8 26 01 00 00 } //2
		$a_00_1 = {52 75 6e 5f 53 69 6d 70 6c 65 53 74 72 69 6e 67 46 6c 61 67 73 00 5f 50 79 5f 46 69 6e 61 6c 69 7a 65 00 5f 50 79 5f 49 6e 69 74 69 61 6c 69 7a 65 00 } //1 畒彮楓灭敬瑓楲杮汆条s偟役楆慮楬敺开祐䥟楮楴污穩e
		$a_00_2 = {5f 61 63 74 69 76 61 74 65 53 74 61 67 65 72 } //2 _activateStager
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=4
 
}