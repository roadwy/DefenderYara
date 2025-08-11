
rule Trojan_Win32_Lazy_BSA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 48 52 30 63 44 6f 76 4c 7a 67 30 4c 6a 49 30 4e 79 34 78 4e 7a 41 75 4d 6a 4d 33 4f 6a 51 34 4e 54 67 76 5a 6d 78 35 58 32 4a 68 59 32 73 3d } //30 aHR0cDovLzg0LjI0Ny4xNzAuMjM3OjQ4NTgvZmx5X2JhY2s=
		$a_81_1 = {53 63 72 65 65 6e 43 61 70 2e 70 6e 67 } //10 ScreenCap.png
		$a_81_2 = {70 6b 69 6c 6c } //5 pkill
		$a_81_3 = {73 68 65 6c 6c 65 78 65 63 } //3 shellexec
		$a_81_4 = {75 70 6c 6f 61 64 } //2 upload
	condition:
		((#a_81_0  & 1)*30+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=50
 
}