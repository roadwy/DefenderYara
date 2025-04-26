
rule Trojan_Win32_Fedcept_C{
	meta:
		description = "Trojan:Win32/Fedcept.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 54 41 4e 44 41 52 54 5f 43 4f 44 45 43 5f 4e 41 47 } //1 STANDART_CODEC_NAG
		$a_01_1 = {76 69 64 65 6f 63 6f 64 65 63 73 75 69 74 65 2e 6e 65 74 2f 74 68 61 6e 6b 79 6f 75 2e 68 74 6d 6c } //1 videocodecsuite.net/thankyou.html
		$a_01_2 = {46 52 45 44 45 58 45 00 } //1 剆䑅塅E
		$a_01_3 = {44 3a 5c 57 6f 72 6b 5c 53 70 79 57 61 72 65 50 72 6a 5c 44 65 73 6b 54 6f 70 5c 43 6f 6d 6d 6f 6e 55 6e 69 74 73 5c 49 44 68 74 74 70 2e 70 61 73 } //1 D:\Work\SpyWarePrj\DeskTop\CommonUnits\IDhttp.pas
		$a_01_4 = {63 3a 5c 64 62 67 5f 61 6c 6c 6f 77 5f 64 65 74 65 63 74 00 } //1 㩣摜杢慟汬睯摟瑥捥t
		$a_03_5 = {61 6e 61 6c 79 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 73 61 6e 64 62 6f 78 00 } //1
		$a_00_6 = {3c 66 72 65 64 5f 6c 69 62 5f 66 69 6c 65 33 32 20 6e 61 6d 65 3d 22 46 52 65 64 33 32 2e 64 6c 6c 22 20 2f 3e } //1 <fred_lib_file32 name="FRed32.dll" />
		$a_01_7 = {49 74 20 69 73 20 6e 6f 74 20 6a 75 73 74 20 61 20 72 61 6e 64 6f 6d 20 62 75 6e 63 68 20 6f 66 20 73 74 75 66 66 20 74 68 72 6f 77 6e 20 74 6f 67 65 74 68 65 72 2e } //1 It is not just a random bunch of stuff thrown together.
		$a_01_8 = {49 00 4e 00 46 00 45 00 43 00 54 00 45 00 44 00 5f 00 50 00 08 00 4d 00 41 00 4c 00 46 00 4f 00 55 00 4e 00 44 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}