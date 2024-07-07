
rule Ransom_Win32_Pyunsam_SA_MTB{
	meta:
		description = "Ransom:Win32/Pyunsam.SA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 70 79 20 25 74 65 6d 70 25 5c 70 61 79 69 6e 67 5c 70 61 79 2d 74 6f 2d 75 6e 6c 6f 63 6b 2e 74 78 74 20 25 53 79 73 74 65 6d 44 72 69 76 65 25 } //1 copy %temp%\paying\pay-to-unlock.txt %SystemDrive%
		$a_01_1 = {64 65 6c 20 2f 71 20 2f 73 20 2f 66 20 25 74 65 6d 70 25 5c 70 61 79 69 6e 67 5c 70 61 79 2d 74 6f 2d 75 6e 6c 6f 63 6b 2e 65 78 65 } //1 del /q /s /f %temp%\paying\pay-to-unlock.exe
		$a_01_2 = {55 00 6e 00 6c 00 6f 00 63 00 6b 00 20 00 4d 00 65 00 20 00 41 00 66 00 74 00 65 00 72 00 20 00 50 00 61 00 79 00 6d 00 65 00 6e 00 74 00 } //1 Unlock Me After Payment
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}