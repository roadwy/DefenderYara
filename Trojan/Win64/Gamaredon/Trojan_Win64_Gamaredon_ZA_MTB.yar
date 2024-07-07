
rule Trojan_Win64_Gamaredon_ZA_MTB{
	meta:
		description = "Trojan:Win64/Gamaredon.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 = createobject("wscript.shell")
		$a_01_1 = {2e 52 75 6e 20 22 69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 73 22 2c 20 30 2c 20 54 52 55 45 } //10 .Run "ipconfig /flushdns", 0, TRUE
		$a_03_2 = {2e 52 75 6e 20 22 77 73 63 72 69 70 74 2e 65 78 65 20 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 90 02 20 2e 64 6c 6c 20 2f 2f 65 3a 56 42 53 63 72 69 70 74 20 2f 2f 62 22 2c 20 30 2c 20 54 52 55 45 90 00 } //10
		$a_01_3 = {2e 44 65 6c 65 74 65 46 69 6c 65 28 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 29 } //1 .DeleteFile("C:\myapp.exe")
		$a_01_4 = {2e 44 65 6c 65 74 65 46 69 6c 65 28 22 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c } //1 .DeleteFile("C:\Documents and Settings\Administrator\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}