
rule Trojan_Win64_Dizzyvoid_E_dha{
	meta:
		description = "Trojan:Win64/Dizzyvoid.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 2b 00 3a 00 25 00 64 00 2f 00 25 00 73 00 } //1 https://+:%d/%s
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 2b 00 3a 00 25 00 64 00 2f 00 25 00 73 00 } //1 http://+:%d/%s
		$a_01_2 = {45 52 52 4f 52 5f 49 4f 5f 50 45 4e 44 49 4e 47 } //1 ERROR_IO_PENDING
		$a_01_3 = {6a 66 6b 64 6a 76 65 75 6a 76 70 64 66 6a 67 64 33 34 3d 2d 33 32 31 } //1 jfkdjveujvpdfjgd34=-321
		$a_01_4 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 66 6f 6e 74 2e 74 6d 70 } //1 c:\windows\temp\font.tmp
		$a_01_5 = {39 26 6d 4e 46 38 5e 4b 33 69 46 55 74 73 70 34 } //1 9&mNF8^K3iFUtsp4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}