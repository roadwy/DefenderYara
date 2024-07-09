
rule Trojan_BAT_FormBook_AFM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 17 58 08 5d 13 0d 02 07 11 0a 91 11 0c 61 07 11 0d 91 59 28 ?? 00 00 06 13 0e 11 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFM_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 8e 69 5d 91 13 06 08 11 05 1f 16 5d 91 13 07 07 11 05 07 11 05 91 11 07 61 11 06 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 05 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFM_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0d 2b 29 11 34 11 0d 1d 5f 91 13 1f 11 1f 19 62 11 1f 1b 63 60 d2 13 1f 11 05 11 0d 11 05 11 0d 91 11 1f 61 d2 9c 11 0d 17 58 13 0d 11 0d 11 08 32 d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFM_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 21 00 02 7b ?? 00 00 04 11 05 02 7b ?? 00 00 04 11 05 91 20 e5 05 00 00 59 d2 9c 00 11 05 17 58 13 05 11 05 02 7b ?? 00 00 04 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFM_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 1d 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 09 18 58 0d 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d d4 } //2
		$a_01_1 = {51 75 61 6e 4c 79 42 61 6e 48 61 6e 67 } //1 QuanLyBanHang
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFM_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 06 6f 7e 00 00 0a 03 73 7f 00 00 0a 0b de 14 0c 08 6f 73 00 00 0a 73 5f 00 00 06 73 80 00 00 0a 0b de } //1
		$a_01_1 = {0a 07 03 6f 9b 00 00 06 07 06 6f 6c 00 00 0a 6f 9d 00 00 06 07 06 6f 79 00 00 0a 6f a3 00 00 06 07 06 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_AFM_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 17 8d 08 00 00 01 25 16 7e 4b 00 00 04 a2 13 06 72 f2 16 00 70 72 bf 18 00 70 72 01 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 07 11 07 09 11 05 14 14 11 06 } //2
		$a_01_1 = {41 00 76 00 74 00 6f 00 70 00 61 00 72 00 6b 00 2e 00 65 00 78 00 65 00 } //1 Avtopark.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFM_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 9a 0c 08 19 8d ?? ?? ?? 01 25 16 7e 2b 00 00 04 16 9a a2 25 17 7e 2b 00 00 04 17 9a a2 25 18 } //2
		$a_03_1 = {16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 07 17 58 0b 07 06 8e 69 } //2
		$a_01_2 = {41 53 31 41 43 68 6f 77 64 68 75 72 79 } //1 AS1AChowdhury
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_AFM_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 1b 59 1c 58 } //2
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {43 00 44 00 6f 00 77 00 6e 00 } //1 CDown
		$a_01_3 = {52 65 73 75 6d 65 50 6f 72 74 72 61 69 74 } //1 ResumePortrait
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_AFM_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 3d 9d 6f ?? 00 00 0a 0c 08 16 9a 6f ?? 00 00 0a 13 06 11 06 72 ?? 09 00 70 28 ?? 00 00 0a 2d 02 2b 21 08 17 9a 6f } //2
		$a_01_1 = {6d 79 54 61 73 6b 53 63 68 65 64 75 6c 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 6d 79 54 61 73 6b 53 63 68 65 64 75 6c 65 72 2e 70 64 62 } //1 myTaskScheduler\obj\Debug\myTaskScheduler.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFM_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 00 6f 00 4c 00 6f 00 63 00 6b 00 20 00 76 00 32 00 20 00 42 00 65 00 74 00 61 00 } //1 FoLock v2 Beta
		$a_01_1 = {53 00 69 00 67 00 6e 00 20 00 55 00 70 00 20 00 66 00 6f 00 72 00 20 00 46 00 6f 00 4c 00 6f 00 63 00 6b 00 } //1 Sign Up for FoLock
		$a_01_2 = {53 00 61 00 61 00 4e 00 5c 00 53 00 61 00 68 00 61 00 6e 00 5c 00 53 00 61 00 61 00 6e 00 20 00 41 00 6c 00 6c 00 5c 00 53 00 61 00 68 00 61 00 6e 00 5c 00 53 00 61 00 68 00 61 00 6e 00 5c 00 4d 00 79 00 20 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 46 00 6f 00 4c 00 6f 00 63 00 6b 00 20 00 56 00 32 00 5c 00 46 00 6f 00 4c 00 6f 00 63 00 6b 00 20 00 56 00 32 00 2e 00 61 00 63 00 63 00 64 00 62 00 } //1 SaaN\Sahan\Saan All\Sahan\Sahan\My Projects\FoLock V2\FoLock V2.accdb
		$a_01_3 = {4a 00 41 00 4d 00 20 00 69 00 73 00 20 00 61 00 6e 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 64 00 65 00 73 00 69 00 67 00 6e 00 65 00 64 00 20 00 66 00 6f 00 72 00 20 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 20 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //1 JAM is an application software designed for personal folder security
		$a_01_4 = {54 00 68 00 65 00 20 00 52 00 45 00 41 00 56 00 49 00 53 00 20 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 } //1 The REAVIS Project
		$a_01_5 = {4a 00 41 00 4d 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 } //1 JAM Folder Protector
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}