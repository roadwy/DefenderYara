
rule TrojanDropper_Win32_Hupigon{
	meta:
		description = "TrojanDropper:Win32/Hupigon,SIGNATURE_TYPE_PEHSTR,08 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {c7 03 30 00 00 00 c7 43 04 02 00 00 00 c7 43 08 03 00 00 00 33 c0 89 43 0c 33 c0 89 43 10 33 c0 89 43 14 33 c0 89 43 18 68 } //2
		$a_01_1 = {47 50 69 67 65 6f 6e 35 5f 53 68 61 72 65 64 } //2 GPigeon5_Shared
		$a_01_2 = {48 55 49 47 45 5a 56 49 50 5f 4d 55 54 45 58 } //2 HUIGEZVIP_MUTEX
		$a_01_3 = {47 52 41 59 50 49 47 45 4f 4e } //2 GRAYPIGEON
		$a_01_4 = {ff ff ff ff 2e 00 00 00 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //2
		$a_01_5 = {53 45 56 49 4e 46 4f } //1 SEVINFO
		$a_01_6 = {ff ff ff ff 04 00 00 00 2e 4e 45 57 } //1
		$a_01_7 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SoftWare\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}