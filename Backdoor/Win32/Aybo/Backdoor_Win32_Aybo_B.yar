
rule Backdoor_Win32_Aybo_B{
	meta:
		description = "Backdoor:Win32/Aybo.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 43 48 54 41 53 4b 53 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 52 65 67 55 70 64 61 74 65 20 2f 53 43 20 6f 6e 73 74 61 72 74 } //1 SCHTASKS /Create /TN RegUpdate /SC onstart
		$a_01_1 = {74 6d 70 64 72 76 2e 65 78 65 } //1 tmpdrv.exe
		$a_01_2 = {41 79 61 62 6f 74 } //1 Ayabot
		$a_01_3 = {63 6c 61 73 73 65 73 2f 73 2e 70 68 70 } //1 classes/s.php
		$a_01_4 = {30 39 34 32 63 33 61 61 64 32 37 38 63 65 35 65 61 35 37 31 61 36 31 37 31 32 62 34 35 30 36 61 2e 70 68 70 } //1 0942c3aad278ce5ea571a61712b4506a.php
		$a_01_5 = {61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 22 53 65 63 75 72 69 74 79 20 46 69 78 22 20 70 72 6f 74 6f 63 6f 6c 3d 54 43 50 20 64 69 72 3d 69 6e 20 6c 6f 63 61 6c 70 6f 72 74 3d 34 34 35 20 61 63 74 69 6f 6e 3d 62 6c 6f 63 6b } //1 add rule name="Security Fix" protocol=TCP dir=in localport=445 action=block
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}