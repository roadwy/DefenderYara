
rule Trojan_Win64_Lazy_SXM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,38 00 38 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 45 18 4c 8d 4d 08 48 83 7d 20 0f 4c 0f 47 4d 08 48 8d 55 e8 48 83 7d 00 07 48 0f 47 55 e8 4c 89 64 24 30 89 44 24 28 89 44 24 20 } //10
		$a_80_1 = {63 6d 64 20 2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 32 20 3e 6e 75 6c 20 26 20 64 65 6c 20 2f 66 20 2f 71 20 } //cmd /c timeout /t 2 >nul & del /f /q   20
		$a_80_2 = {63 6d 64 20 2f 63 20 6a 61 76 61 20 2d 76 65 72 73 69 6f 6e 20 3e 6e 75 6c 20 32 3e 26 31 } //cmd /c java -version >nul 2>&1  20
		$a_80_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 22 45 78 70 61 6e 64 2d 41 72 63 68 69 76 65 20 2d 50 61 74 68 20 27 } //powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Path '  2
		$a_80_4 = {5c 61 2e 74 78 74 } //\a.txt  2
		$a_80_5 = {70 6f 77 65 72 63 61 74 2e 64 6f 67 } //powercat.dog  2
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*20+(#a_80_2  & 1)*20+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=56
 
}