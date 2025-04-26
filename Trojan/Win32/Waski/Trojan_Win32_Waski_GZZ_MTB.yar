
rule Trojan_Win32_Waski_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Waski.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {10 56 8b f1 57 8d 46 08 33 ff 39 38 74 12 50 e8 b7 ea ff ff 83 c4 04 ff 46 0c 5f 5e 8b e5 5d c3 } //1
		$a_01_1 = {31 38 38 2e 32 35 35 2e 32 33 39 2e 33 34 } //1 188.255.239.34
		$a_01_2 = {31 37 33 2e 32 34 33 2e 32 35 35 2e 37 39 } //1 173.243.255.79
		$a_01_3 = {6f 66 79 6c 79 77 6f 2e 65 78 65 } //1 ofylywo.exe
		$a_01_4 = {62 6c 6f 6f 73 69 64 2e 65 78 65 } //1 bloosid.exe
		$a_01_5 = {2f 67 31 31 2e 70 6e 67 } //1 /g11.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}