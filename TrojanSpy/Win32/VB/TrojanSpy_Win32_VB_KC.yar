
rule TrojanSpy_Win32_VB_KC{
	meta:
		description = "TrojanSpy:Win32/VB.KC,SIGNATURE_TYPE_PEHSTR,14 00 0f 00 12 00 00 "
		
	strings :
		$a_01_0 = {21 00 21 00 21 00 21 00 27 00 27 00 27 00 54 00 70 00 54 00 41 00 79 00 61 00 72 00 6c 00 61 00 72 00 42 00 } //5 !!!!'''TpTAyarlarB
		$a_01_1 = {73 00 70 00 79 00 73 00 69 00 6c 00 69 00 63 00 69 00 2e 00 62 00 61 00 74 00 } //1 spysilici.bat
		$a_01_2 = {54 00 70 00 54 00 20 00 53 00 70 00 79 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 56 00 31 00 2e 00 30 00 20 00 28 00 4c 00 6f 00 61 00 64 00 65 00 64 00 20 00 41 00 74 00 20 00 } //5 TpT Spy Keylogger V1.0 (Loaded At 
		$a_01_3 = {20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 20 00 53 00 69 00 73 00 74 00 65 00 6d 00 20 00 42 00 69 00 6c 00 67 00 69 00 73 00 69 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 } //1  ***************** Sistem Bilgisi *****************
		$a_01_4 = {6c 00 65 00 6d 00 6c 00 65 00 72 00 20 00 4c 00 69 00 73 00 74 00 65 00 73 00 69 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 } //1 lemler Listesi *****************
		$a_01_5 = {20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 20 00 50 00 61 00 6e 00 6f 00 20 00 44 00 65 00 } //1  ***************** Pano De
		$a_01_6 = {69 00 6d 00 6c 00 65 00 72 00 69 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 } //1 imleri *****************
		$a_01_7 = {20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 20 00 4b 00 6c 00 61 00 76 00 79 00 65 00 20 00 47 00 69 00 72 00 64 00 69 00 6c 00 65 00 72 00 69 00 20 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 2a 00 } //1  ***************** Klavye Girdileri *****************
		$a_01_8 = {53 00 69 00 73 00 74 00 65 00 6d 00 20 00 62 00 69 00 6c 00 67 00 69 00 73 00 69 00 20 00 3a 00 20 00 } //1 Sistem bilgisi : 
		$a_01_9 = {6c 00 65 00 6d 00 63 00 69 00 3a 00 20 00 } //1 lemci: 
		$a_01_10 = {54 00 6f 00 70 00 6c 00 61 00 6d 00 20 00 42 00 65 00 6c 00 6c 00 65 00 6b 00 3a 00 20 00 } //1 Toplam Bellek: 
		$a_01_11 = {57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 20 00 56 00 65 00 72 00 73 00 69 00 79 00 6f 00 6e 00 75 00 3a 00 20 00 } //1 WINDOWS Versiyonu: 
		$a_01_12 = {42 00 69 00 6c 00 67 00 69 00 73 00 61 00 79 00 61 00 72 00 20 00 41 00 64 00 } //1 Bilgisayar Ad
		$a_01_13 = {40 00 54 00 70 00 54 00 4c 00 61 00 62 00 73 00 2e 00 63 00 6f 00 6d 00 } //1 @TpTLabs.com
		$a_01_14 = {20 00 5b 00 20 00 43 00 61 00 70 00 73 00 6c 00 6f 00 63 00 6b 00 3d 00 41 00 } //1  [ Capslock=A
		$a_01_15 = {20 00 5b 00 20 00 43 00 61 00 70 00 73 00 6c 00 6f 00 63 00 6b 00 3d 00 4b 00 61 00 70 00 61 00 6c 00 } //1  [ Capslock=Kapal
		$a_01_16 = {20 00 5b 00 20 00 4e 00 75 00 6d 00 6c 00 6f 00 63 00 6b 00 3d 00 41 00 } //1  [ Numlock=A
		$a_01_17 = {20 00 5b 00 20 00 4e 00 75 00 6d 00 6c 00 6f 00 63 00 6b 00 3d 00 4b 00 61 00 70 00 61 00 6c 00 } //1  [ Numlock=Kapal
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=15
 
}