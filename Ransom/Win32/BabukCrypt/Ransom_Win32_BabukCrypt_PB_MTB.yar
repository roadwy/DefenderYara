
rule Ransom_Win32_BabukCrypt_PB_MTB{
	meta:
		description = "Ransom:Win32/BabukCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 /c vssadmin.exe delete shadows /all /quiet
		$a_01_1 = {48 00 6f 00 77 00 20 00 54 00 6f 00 20 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 How To Restore Your Files.txt
		$a_01_2 = {44 6f 59 6f 75 57 61 6e 74 54 6f 48 61 76 65 53 65 78 57 69 74 68 43 75 6f 6e 67 44 6f 6e 67 } //1 DoYouWantToHaveSexWithCuongDong
		$a_01_3 = {2e 00 62 00 61 00 62 00 79 00 6b 00 } //1 .babyk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}