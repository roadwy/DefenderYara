
rule Trojan_Win32_Redline_ASAO_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b c8 e8 ?? ?? 00 00 8b 55 08 03 55 fc 0f b6 02 83 c0 ?? 8b 4d 08 03 4d fc 88 01 e9 } //1
		$a_03_1 = {8b 55 08 03 55 fc 0f b6 02 35 ?? 00 00 00 8b 4d 08 03 4d fc 88 01 68 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Redline_ASAO_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.ASAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 00 65 00 77 00 6f 00 6c 00 6f 00 67 00 69 00 77 00 65 00 78 00 6f 00 76 00 61 00 76 00 75 00 63 00 6f 00 62 00 6f 00 73 00 6f 00 72 00 75 00 7a 00 75 00 6c 00 61 00 68 00 61 00 67 00 } //1 rewologiwexovavucobosoruzulahag
		$a_01_1 = {79 00 69 00 67 00 65 00 77 00 6f 00 6d 00 6f 00 63 00 6f 00 6e 00 61 00 67 00 75 00 66 00 6f 00 66 00 69 00 6c 00 65 00 6a 00 20 00 6b 00 65 00 6d 00 6f 00 6d 00 6f 00 68 00 6f 00 6b 00 65 00 62 00 61 00 76 00 65 00 64 00 61 00 67 00 65 00 6c 00 75 00 6d 00 65 00 7a 00 75 00 62 00 6f 00 77 00 6f 00 20 00 6e 00 61 00 62 00 6f 00 6a 00 65 00 6a 00 75 00 73 00 6f 00 79 00 6f 00 68 00 65 00 63 00 6f 00 64 00 65 00 7a 00 20 00 64 00 6f 00 6c 00 20 00 64 00 75 00 6c 00 61 00 6b 00 75 00 } //1 yigewomoconagufofilej kemomohokebavedagelumezubowo nabojejusoyohecodez dol dulaku
		$a_01_2 = {52 00 75 00 6c 00 75 00 79 00 20 00 78 00 61 00 6d 00 75 00 6a 00 75 00 68 00 61 00 67 00 6f 00 66 00 61 00 6e 00 20 00 70 00 6f 00 6e 00 69 00 7a 00 75 00 20 00 77 00 69 00 63 00 75 00 70 00 6f 00 7a 00 69 00 67 00 6f 00 6d 00 61 00 7a 00 75 00 20 00 68 00 61 00 68 00 75 00 73 00 75 00 62 00 61 00 6b 00 6f 00 72 00 } //1 Ruluy xamujuhagofan ponizu wicupozigomazu hahusubakor
		$a_01_3 = {76 00 61 00 67 00 75 00 68 00 65 00 73 00 61 00 77 00 69 00 20 00 72 00 61 00 64 00 61 00 6c 00 75 00 78 00 61 00 6b 00 65 00 79 00 69 00 68 00 } //1 vaguhesawi radaluxakeyih
		$a_01_4 = {73 75 74 69 6e 69 73 61 70 61 68 65 72 69 6b 61 78 6f 68 65 67 6f 67 65 70 6f 76 6f 76 20 68 69 64 75 77 61 6d 69 66 65 72 75 79 61 68 65 63 65 6d 75 67 69 77 61 77 20 77 65 74 65 6b 75 6c 6f 6c 20 63 6f 67 69 6e 61 6e 69 6a 6f 70 69 7a 6f 6c 6f 78 75 76 61 64 65 67 61 63 69 64 61 77 75 78 61 } //1 sutinisapaherikaxohegogepovov hiduwamiferuyahecemugiwaw wetekulol coginanijopizoloxuvadegacidawuxa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}