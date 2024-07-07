
rule Trojan_Win32_Zbot_R_MTB{
	meta:
		description = "Trojan:Win32/Zbot.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 77 00 73 00 6e 00 70 00 6f 00 65 00 6d 00 5c 00 76 00 69 00 64 00 65 00 6f 00 2e 00 64 00 6c 00 6c 00 } //1 Application Data\wsnpoem\video.dll
		$a_01_1 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 62 63 5a } //1 zkrvvcnmaebNbcZ
		$a_01_2 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 58 4d 5a 5b 51 52 49 } //1 fk{vtelpp]hg[_\HXMZ[QRI
		$a_01_3 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 55 66 5c 56 57 58 49 54 } //1 zkrvvcnmaebNUf\VWXIT
		$a_01_4 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 61 51 54 50 51 47 4d 4a } //1 fk{vtelpp]hg[_\HaQTPQGMJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Zbot_R_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 73 00 6e 00 70 00 6f 00 65 00 6d 00 5c 00 76 00 69 00 64 00 65 00 6f 00 2e 00 64 00 6c 00 6c 00 } //1 WINDOWS\system32\wsnpoem\video.dll
		$a_01_1 = {57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 74 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //1 WINDOWS\system32\ntos.exe
		$a_01_2 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 62 63 5a } //1 zkrvvcnmaebNbcZ
		$a_01_3 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 58 4d 5a 5b 51 52 49 } //1 fk{vtelpp]hg[_\HXMZ[QRI
		$a_01_4 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 55 66 5c 56 57 58 49 54 } //1 zkrvvcnmaebNUf\VWXIT
		$a_01_5 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 61 51 54 50 51 47 4d 4a } //1 fk{vtelpp]hg[_\HaQTPQGMJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Zbot_R_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 65 00 63 00 6b 00 59 00 49 00 6b 00 59 00 55 00 49 00 38 00 } //1 CompanyNameeckYIkYUI8
		$a_01_1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 78 00 64 00 68 00 66 00 39 00 4a 00 54 00 76 00 37 00 } //1 OriginalFilenamexdhf9JTv7
		$a_01_2 = {57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 74 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //1 WINDOWS\system32\ntos.exe
		$a_01_3 = {39 00 6a 00 62 00 72 00 4e 00 4e 00 78 00 5a 00 } //1 9jbrNNxZ
		$a_01_4 = {65 00 57 00 6d 00 57 00 4f 00 38 00 43 00 51 00 65 00 } //1 eWmWO8CQe
		$a_01_5 = {6c 00 33 00 44 00 64 00 78 00 74 00 74 00 35 00 66 00 54 00 } //1 l3Ddxtt5fT
		$a_01_6 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 62 63 5a } //1 zkrvvcnmaebNbcZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}