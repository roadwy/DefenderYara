
rule Trojan_Win32_Clicker_RP_MTB{
	meta:
		description = "Trojan:Win32/Clicker.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 6b 2e 65 78 65 } //1 ok.exe
		$a_01_1 = {44 3a 5c 50 72 6f 6a 65 63 74 73 5c 4e 65 77 5c 41 70 70 5c 41 70 70 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 6e 65 77 5c 6f 6b 2e 70 64 62 } //1 D:\Projects\New\App\App\bin\Release\new\ok.pdb
		$a_01_2 = {70 00 6c 00 61 00 79 00 6e 00 65 00 77 00 28 00 29 00 3b 00 } //1 playnew();
		$a_01_3 = {74 00 67 00 62 00 6e 00 68 00 79 00 } //1 tgbnhy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}