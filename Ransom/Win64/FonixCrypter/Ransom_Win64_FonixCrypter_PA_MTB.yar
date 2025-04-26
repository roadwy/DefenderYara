
rule Ransom_Win64_FonixCrypter_PA_MTB{
	meta:
		description = "Ransom:Win64/FonixCrypter.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {58 00 69 00 6e 00 6f 00 66 00 53 00 65 00 74 00 75 00 70 00 2e 00 62 00 61 00 74 00 } //1 XinofSetup.bat
		$a_01_1 = {48 00 6f 00 77 00 20 00 54 00 6f 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 46 00 69 00 6c 00 65 00 73 00 2e 00 68 00 74 00 61 00 } //1 How To Decrypt Files.hta
		$a_01_2 = {5c 00 48 00 65 00 6c 00 70 00 2e 00 74 00 78 00 74 00 } //1 \Help.txt
		$a_00_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 58 49 4e 4f 46 2e 65 78 65 } //1 \Microsoft\Windows\Start Menu\Programs\Startup\XINOF.exe
		$a_00_4 = {2f 63 20 76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 20 26 20 77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 /c vssadmin Delete Shadows /All /Quiet & wmic shadowcopy delete
		$a_01_5 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 58 00 49 00 4e 00 4f 00 46 00 42 00 47 00 2e 00 6a 00 70 00 67 00 } //1 C:\ProgramData\XINOFBG.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}