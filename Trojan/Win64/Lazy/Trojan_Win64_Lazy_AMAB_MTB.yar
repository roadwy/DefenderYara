
rule Trojan_Win64_Lazy_AMAB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6f 70 65 6e 63 76 5f 77 6f 72 6c 64 34 37 30 2e 64 6c 6c } //1 C:\Windows\System32\opencv_world470.dll
		$a_81_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 64 73 35 77 5f 78 36 34 2e 64 6c 6c } //1 C:\Windows\System32\ds5w_x64.dll
		$a_81_2 = {63 64 6e 2e 61 78 69 6f 6e 2e 73 79 73 74 65 6d 73 2f 64 69 61 62 6c 6f 2f 63 66 34 34 36 33 66 38 2d 36 64 62 39 2d 34 61 38 62 2d 39 39 32 35 2d 31 36 61 39 39 61 31 62 64 65 63 32 2e 65 78 65 } //1 cdn.axion.systems/diablo/cf4463f8-6db9-4a8b-9925-16a99a1bdec2.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}