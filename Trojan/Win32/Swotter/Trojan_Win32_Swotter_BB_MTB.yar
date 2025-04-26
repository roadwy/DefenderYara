
rule Trojan_Win32_Swotter_BB_MTB{
	meta:
		description = "Trojan:Win32/Swotter.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_02_0 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 90 05 15 03 61 2d 7a 2c 50 72 65 74 6f 72 } //1
		$a_02_1 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 90 05 15 03 61 2d 7a 2c 42 65 6e 74 6c 65 79 } //1
		$a_02_2 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 90 05 15 03 61 2d 7a 2c 58 79 6c 6f 6c } //1
		$a_00_3 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //2 Nullsoft Install System
		$a_00_4 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 55 6c 6f 74 72 69 63 68 79 2c 53 63 72 65 65 6e 69 6e 67 } //1 %%\rundll32.exe Ulotrichy,Screening
		$a_00_5 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 46 65 73 74 6f 6f 6e 65 72 79 2c 42 65 6e 74 6c 65 79 } //1 %%\rundll32.exe Festoonery,Bentley
		$a_00_6 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 52 65 6e 6f 76 61 74 6f 72 2c 57 6f 72 64 62 6f 6f 6b } //1 \rundll32.exe Renovator,Wordbook
		$a_00_7 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 53 6c 75 67 66 65 73 74 2c 42 65 6e 74 6c 65 79 } //1 %%\rundll32.exe Slugfest,Bentley
		$a_00_8 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 42 72 69 64 65 73 6d 61 69 64 2c 4d 69 6e 79 61 6e } //1 %%\rundll32.exe Bridesmaid,Minyan
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=3
 
}