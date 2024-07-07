
rule TrojanDropper_Win32_Clicker{
	meta:
		description = "TrojanDropper:Win32/Clicker,SIGNATURE_TYPE_PEHSTR,34 00 34 00 0a 00 00 "
		
	strings :
		$a_01_0 = {5c 3f 3f 5c 25 73 } //10 \??\%s
		$a_01_1 = {69 6e 73 74 61 6c 6c 68 6f 6f 6b } //10 installhook
		$a_01_2 = {5c 73 76 63 68 30 73 74 2e 65 78 65 } //10 \svch0st.exe
		$a_01_3 = {5c 63 68 65 61 6b 6f 75 74 2e 69 6e 69 } //10 \cheakout.ini
		$a_01_4 = {35 39 38 43 33 33 43 42 2d 35 31 30 45 2d 34 38 35 37 2d 39 38 30 31 2d 37 38 46 31 44 38 39 32 38 37 39 43 } //10 598C33CB-510E-4857-9801-78F1D892879C
		$a_01_5 = {64 65 6c 20 25 30 } //1 del %0
		$a_01_6 = {5c 64 65 6c 2e 62 61 74 } //1 \del.bat
		$a_01_7 = {67 6f 74 6f 20 64 65 6c 6c 6f 6f 70 } //1 goto delloop
		$a_01_8 = {5a 77 4c 6f 61 64 44 72 69 76 65 72 } //1 ZwLoadDriver
		$a_01_9 = {2f 63 6c 63 6f 75 6e 74 2f 63 6f 75 6e 74 2e 61 73 70 3f 61 63 74 69 6f 6e 3d 69 6e 73 74 61 6c 6c 26 76 65 72 3d } //1 /clcount/count.asp?action=install&ver=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=52
 
}