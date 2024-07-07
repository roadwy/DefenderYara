
rule TrojanDropper_Win32_Pykspa_A{
	meta:
		description = "TrojanDropper:Win32/Pykspa.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {8d 85 d8 fd ff ff 50 0f be 85 d8 fd ff ff 99 b9 05 00 00 00 f7 f9 83 c2 06 52 8d 95 b4 fd ff ff 52 e8 } //2
		$a_03_1 = {0f be 8d aa fd ff ff 85 c9 75 0b 0f be 95 8f fc ff ff 85 d2 75 0b 0f b6 85 d7 fd ff ff 85 c0 74 19 0f b6 8d d7 fd ff ff 85 c9 0f 84 90 01 02 00 00 83 7d fc 78 0f 8e 90 01 02 00 00 c7 45 fc 00 00 00 00 90 00 } //2
		$a_01_2 = {00 2e 64 00 00 6c 6c 00 } //2 ⸀d氀l
		$a_03_3 = {00 2e 65 00 00 78 90 02 03 65 00 90 00 } //2
		$a_01_4 = {00 73 6f 75 70 38 38 00 } //1 猀畯㡰8
		$a_01_5 = {00 74 76 66 31 00 } //1 琀晶1
		$a_01_6 = {00 73 61 74 31 31 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}