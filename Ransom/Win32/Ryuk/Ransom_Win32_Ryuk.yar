
rule Ransom_Win32_Ryuk{
	meta:
		description = "Ransom:Win32/Ryuk,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 00 79 00 75 00 6b 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 RyukReadMe.txt
		$a_01_1 = {72 00 73 00 61 00 20 00 6b 00 65 00 79 00 73 00 } //1 rsa keys
		$a_01_2 = {24 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 2e 00 42 00 69 00 6e 00 } //1 $Recycle.Bin
		$a_01_3 = {63 61 6e 74 20 63 68 65 63 6b 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2c 20 73 74 61 72 74 20 44 45 43 52 59 50 54 4f 52 20 77 69 74 68 20 61 64 6d 69 6e 69 73 74 72 61 74 69 76 65 20 70 72 69 76 69 6c 65 67 65 73 } //1 cant check information, start DECRYPTOR with administrative privileges
		$a_01_4 = {77 72 69 74 65 20 66 75 6c 6c 20 61 64 64 72 65 73 73 20 6f 66 20 66 69 6c 65 2c 20 65 78 61 6d 70 6c 65 } //1 write full address of file, example
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Ransom_Win32_Ryuk_2{
	meta:
		description = "Ransom:Win32/Ryuk,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 4d 00 63 00 41 00 66 00 65 00 65 00 44 00 4c 00 50 00 41 00 67 00 65 00 6e 00 74 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 net stop McAfeeDLPAgentService
		$a_01_1 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 73 00 61 00 6d 00 73 00 73 00 } //1 net stop samss
		$a_01_2 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 49 00 4d 00 20 00 73 00 71 00 6c 00 77 00 72 00 69 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 taskkill /IM sqlwriter.exe
		$a_01_3 = {77 00 6d 00 69 00 70 00 72 00 76 00 73 00 65 00 20 00 2d 00 45 00 6d 00 62 00 65 00 64 00 64 00 69 00 6e 00 67 00 } //1 wmiprvse -Embedding
		$a_01_4 = {69 00 63 00 61 00 63 00 6c 00 73 00 20 00 22 00 43 00 3a 00 5c 00 2a 00 22 00 20 00 2f 00 67 00 72 00 61 00 6e 00 74 00 20 00 45 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 3a 00 46 00 20 00 2f 00 54 00 20 00 2f 00 43 00 20 00 2f 00 51 00 } //1 icacls "C:\*" /grant Everyone:F /T /C /Q
		$a_01_5 = {2d 00 65 00 2c 00 2d 00 2d 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 20 00 6f 00 70 00 74 00 69 00 6f 00 6e 00 20 00 6e 00 65 00 65 00 64 00 65 00 64 00 } //4 -e,--encrypt option needed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*4) >=6
 
}