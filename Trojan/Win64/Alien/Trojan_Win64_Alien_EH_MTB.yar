
rule Trojan_Win64_Alien_EH_MTB{
	meta:
		description = "Trojan:Win64/Alien.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {6d 6b 64 69 72 20 43 3a 5c 50 65 72 66 6f 72 6d } //1 mkdir C:\Perform
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 20 22 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 22 43 3a 5c 50 65 72 66 6f 72 6d 22 } //1 powershell -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath "C:\Perform"
		$a_81_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 22 43 3a 5c 50 65 72 66 6f 72 6d 22 } //1 powershell -Command Add-MpPreference -ExclusionPath "C:\Perform"
		$a_81_3 = {37 7a 61 2e 65 78 65 20 78 20 66 69 6c 65 73 2e 37 7a 20 2d 61 6f 61 20 2d 70 36 48 35 64 37 35 5a 38 51 77 67 45 65 51 79 } //1 7za.exe x files.7z -aoa -p6H5d75Z8QwgEeQy
		$a_81_4 = {3e 6e 75 6c 20 70 69 6e 67 20 2d 6e 20 33 20 6c 6f 63 61 6c 68 6f 73 74 } //1 >nul ping -n 3 localhost
		$a_81_5 = {73 74 61 72 74 20 43 3a 5c 50 65 72 66 6f 72 6d 5c 53 65 74 75 36 34 2e 65 78 65 } //1 start C:\Perform\Setu64.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}