
rule Trojan_Win32_Stonerev_A{
	meta:
		description = "Trojan:Win32/Stonerev.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 53 54 4f 4e 45 53 00 } //1 匀佔䕎S
		$a_01_1 = {65 78 65 2e 79 61 72 74 73 52 } //1 exe.yartsR
		$a_01_2 = {73 25 5c 70 6d 65 54 5c 53 57 4f 44 4e 49 57 5c 3a 43 } //1 s%\pmeT\SWODNIW\:C
		$a_01_3 = {70 5c 57 69 6e 55 70 64 61 74 65 2e 74 6d 70 } //1 p\WinUpdate.tmp
		$a_01_4 = {4c 6f 61 64 65 72 4d 69 72 61 } //1 LoaderMira
		$a_03_5 = {ff 72 c6 85 ?? ff ff ff 5c c6 85 ?? ff ff ff 63 c6 85 ?? ff ff ff 61 c6 85 ?? ff ff ff 72 c6 85 ?? ff ff ff 73 c6 85 ?? ff ff ff 73 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}