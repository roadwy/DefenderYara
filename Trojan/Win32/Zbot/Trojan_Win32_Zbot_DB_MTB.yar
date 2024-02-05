
rule Trojan_Win32_Zbot_DB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 55 73 65 72 73 5c 6b 6c 65 6d 6d 64 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 54 65 6d 70 31 5f 52 65 6d 69 74 5f 61 74 68 20 72 75 2e 7a 69 70 5c 66 61 78 2e 65 78 65 } //C:\Users\klemmd\AppData\Local\Temp\Temp1_Remit_ath ru.zip\fax.exe  01 00 
		$a_80_1 = {43 3a 5c 53 69 46 34 50 49 6c 4b 2e 65 78 65 } //C:\SiF4PIlK.exe  01 00 
		$a_80_2 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 32 64 37 61 64 63 33 32 62 61 65 30 36 62 65 34 66 63 31 37 63 61 37 66 31 35 64 31 61 33 64 39 2e 76 69 72 75 73 2e 65 78 65 } //C:\Users\admin\Downloads\2d7adc32bae06be4fc17ca7f15d1a3d9.virus.exe  01 00 
		$a_80_3 = {43 3a 5c 55 73 65 72 73 5c 67 65 6f 72 67 65 5c 44 65 73 6b 74 6f 70 5c 66 6f 78 75 70 64 61 74 65 72 2e 65 78 65 } //C:\Users\george\Desktop\foxupdater.exe  01 00 
		$a_80_4 = {43 3a 5c 55 73 65 72 73 5c 72 2e 76 75 6c 74 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 64 38 39 66 62 30 36 33 35 31 37 31 32 36 64 31 36 63 66 65 33 62 66 64 30 31 32 30 35 36 36 39 2e 65 78 65 } //C:\Users\r.vult\AppData\Local\Temp\d89fb063517126d16cfe3bfd01205669.exe  00 00 
	condition:
		any of ($a_*)
 
}