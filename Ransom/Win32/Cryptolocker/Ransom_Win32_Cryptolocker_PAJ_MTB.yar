
rule Ransom_Win32_Cryptolocker_PAJ_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.PAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 46 69 6c 65 53 74 72 65 61 6d 57 72 69 74 65 72 2e 57 72 69 74 65 28 5b 53 79 73 74 65 6d 2e 42 69 74 43 6f 6e 76 65 72 74 65 72 5d 3a 3a 47 65 74 42 79 74 65 73 28 24 43 72 79 70 74 6f 2e 49 56 2e 4c 65 6e 67 74 68 29 } //1 $FileStreamWriter.Write([System.BitConverter]::GetBytes($Crypto.IV.Length)
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 50 61 73 73 20 2d 46 69 6c 65 } //1 powershell -ExecutionPolicy ByPass -File
		$a_01_2 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your personal files have been encrypted
		$a_01_3 = {2d 53 75 66 66 69 78 20 27 2e 6c 6f 63 6b 65 64 27 20 2d 52 65 6d 6f 76 65 53 6f 75 72 63 65 } //1 -Suffix '.locked' -RemoveSource
		$a_01_4 = {52 65 61 64 6d 65 5f 6e 6f 77 2e 74 78 74 } //1 Readme_now.txt
		$a_01_5 = {63 72 79 2e 70 73 31 } //1 cry.ps1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}