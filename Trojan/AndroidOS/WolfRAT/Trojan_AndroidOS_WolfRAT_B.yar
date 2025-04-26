
rule Trojan_AndroidOS_WolfRAT_B{
	meta:
		description = "Trojan:AndroidOS/WolfRAT.B,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_01_0 = {65 79 4a 70 63 33 4d 69 4f 69 49 77 4d 44 41 77 4d 44 41 77 4d 44 45 7a 49 69 77 69 61 32 6c 6b 49 6a 6f 69 4d 44 41 77 4d 44 41 77 4d 44 41 78 4d 79 30 77 4c 55 6c 54 53 53 30 30 4d 57 55 32 5a 6a 42 69 4e 53 30 31 4d 6a 51 77 4c 54 51 77 4e 6d 4d 74 59 6a 59 79 4d 53 30 31 4e 44 4e 6c 5a 57 5a 69 59 6a 45 30 4f 44 45 69 4c 43 49 35 59 6a 49 32 4f 57 59 7a 5a 44 46 6d 4e 6a 46 6c 4e 57 5a 68 4d 7a 59 35 4e 53 49 36 64 48 4a 31 5a 58 30 } //1 eyJpc3MiOiIwMDAwMDAwMDEzIiwia2lkIjoiMDAwMDAwMDAxMy0wLUlTSS00MWU2ZjBiNS01MjQwLTQwNmMtYjYyMS01NDNlZWZiYjE0ODEiLCI5YjI2OWYzZDFmNjFlNWZhMzY5NSI6dHJ1ZX0
		$a_00_1 = {73 76 63 77 73 2e 73 6f 6d 74 75 6d 2e 74 6f 64 61 79 } //1 svcws.somtum.today
		$a_00_2 = {42 6f 74 73 2f 67 65 74 5f 75 70 64 61 74 65 } //1 Bots/get_update
		$a_00_3 = {2f 43 6f 6d 6d 61 6e 64 73 2f 63 6f 6d 6d 5f 67 65 74 66 75 6e 63 74 69 6f 6e } //1 /Commands/comm_getfunction
		$a_00_4 = {2f 43 6f 6d 6d 61 6e 64 73 2f 64 65 6c 65 74 65 5f 63 6f 6d 6d } //1 /Commands/delete_comm
		$a_00_5 = {2f 44 6f 77 6e 6c 6f 61 64 2f 75 70 64 61 74 65 2e 61 70 6b } //1 /Download/update.apk
		$a_00_6 = {2f 64 65 6c 65 74 65 5f 66 69 6c 65 } //1 /delete_file
		$a_00_7 = {2f 75 70 6c 6f 61 64 5f 66 69 6c 65 } //1 /upload_file
		$a_00_8 = {2f 4d 65 73 73 61 67 65 73 2f 6d 65 73 73 5f 75 70 64 61 74 65 } //1 /Messages/mess_update
		$a_00_9 = {2f 75 70 6c 6f 61 64 2d 70 69 63 74 75 72 65 73 2e 70 68 70 3f } //1 /upload-pictures.php?
		$a_01_10 = {2f 6d 6e 74 2f 73 64 63 61 72 64 2f 44 6f 77 6e 6c 6f 61 64 2f 75 70 64 61 74 65 2e 61 70 6b } //1 /mnt/sdcard/Download/update.apk
		$a_00_11 = {2f 73 74 6f 72 61 67 65 2f 65 6d 75 6c 61 74 65 64 2f 30 2f 53 79 73 74 65 6d 2f 43 61 6c 6c 73 } //1 /storage/emulated/0/System/Calls
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*1) >=10
 
}