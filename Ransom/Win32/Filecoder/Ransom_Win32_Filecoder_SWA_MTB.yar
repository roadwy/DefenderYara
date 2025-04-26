
rule Ransom_Win32_Filecoder_SWA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //2 /c vssadmin.exe delete shadows /all /quiet
		$a_00_1 = {48 00 6f 00 77 00 20 00 54 00 6f 00 20 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //2 How To Restore Your Files.txt
		$a_01_2 = {44 6f 59 6f 75 57 61 6e 74 54 6f 48 61 76 65 53 65 78 57 69 74 68 43 75 6f 6e 67 44 6f 6e 67 } //1 DoYouWantToHaveSexWithCuongDong
		$a_01_3 = {70 72 6f 63 65 73 73 65 73 20 6b 69 6c 6c 65 72 } //1 processes killer
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}