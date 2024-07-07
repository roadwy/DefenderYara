
rule Ransom_Win32_Contentocrypt_A{
	meta:
		description = "Ransom:Win32/Contentocrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {4a 45 6e 63 72 79 70 74 90 02 20 50 61 73 5a 69 70 90 02 10 43 6f 6e 66 69 67 90 02 20 53 61 6e 64 62 6f 78 65 73 90 00 } //1
		$a_00_1 = {41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 27 29 3b 73 65 74 49 6e 74 65 72 76 61 6c 28 66 75 6e 63 74 69 6f 6e 28 29 7b 74 72 79 7b 6f 2e 44 65 6c 65 74 65 46 69 6c 65 } //1 ActiveXObject('Scripting.FileSystemObject');setInterval(function(){try{o.DeleteFile
		$a_00_2 = {21 21 21 57 41 4c 4c 50 41 50 45 52 21 21 21 } //1 !!!WALLPAPER!!!
		$a_00_3 = {3a 5c 44 45 56 5c 47 4c 4f 42 45 5c 4c 4f 43 4b 45 52 5c 75 42 69 67 49 6e 74 73 56 33 2e 70 61 73 } //2 :\DEV\GLOBE\LOCKER\uBigIntsV3.pas
		$a_03_4 = {2e 65 78 65 20 44 90 02 10 65 6c 65 74 90 02 10 65 20 53 68 61 90 02 10 64 6f 77 73 20 2f 41 90 02 10 6c 6c 20 2f 51 90 02 10 75 69 65 74 90 00 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_03_4  & 1)*2) >=5
 
}