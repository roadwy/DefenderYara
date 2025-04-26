
rule Trojan_Win32_BadJoke_SPLS_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.SPLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {78 20 3d 20 6d 73 67 62 6f 78 28 22 79 6f 75 72 20 70 63 20 69 73 20 68 61 63 6b 65 64 21 22 2c 20 30 2b 34 38 2c 20 22 61 63 68 22 29 } //x = msgbox("your pc is hacked!", 0+48, "ach")  2
		$a_80_1 = {73 74 61 72 74 20 68 74 74 70 73 3a 2f 2f 79 61 6e 64 65 78 2e 72 75 2f 73 65 61 72 63 68 2f 3f 74 65 78 74 3d 79 6f 75 2b 61 72 65 2b 68 61 63 6b 65 64 2b 62 79 2b 61 63 68 2b 76 7a 6c 6f 6d 26 63 6c 69 64 3d 32 34 31 31 37 32 36 26 6c 72 3d 34 33 } //start https://yandex.ru/search/?text=you+are+hacked+by+ach+vzlom&clid=2411726&lr=43  1
		$a_80_2 = {78 20 3d 20 6d 73 67 62 6f 78 28 22 74 68 72 65 61 74 20 6e 61 6d 65 64 20 74 72 6f 6a 61 6e 3a 77 69 6e 33 32 3a 77 69 6e 64 6f 77 73 20 66 6f 75 6e 64 65 64 21 20 79 6f 75 20 6e 65 65 64 20 64 65 6c 65 74 65 20 77 69 6e 64 6f 77 73 21 22 2c 20 30 2b 34 38 2c 20 22 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 22 29 } //x = msgbox("threat named trojan:win32:windows founded! you need delete windows!", 0+48, "windows defender")  1
		$a_80_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //SELECT * FROM Win32_OperatingSystem  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}