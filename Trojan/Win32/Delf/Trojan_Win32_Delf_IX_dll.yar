
rule Trojan_Win32_Delf_IX_dll{
	meta:
		description = "Trojan:Win32/Delf.IX!dll,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 73 72 76 73 79 73 5c } //1 \srvsys\
		$a_01_1 = {5c 77 69 6e 74 65 6d 70 5f 36 34 5c } //1 \wintemp_64\
		$a_01_2 = {2e 36 64 75 64 75 2e 63 6f 6d } //2 .6dudu.com
		$a_01_3 = {62 69 62 69 62 65 69 2e 65 78 65 } //2 bibibei.exe
		$a_01_4 = {31 32 32 2e 32 32 34 2e 39 2e 31 31 33 3a 38 30 32 32 2f 49 6e 73 65 72 74 62 7a 2e 61 73 70 78 3f 6d 63 69 3d } //2 122.224.9.113:8022/Insertbz.aspx?mci=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=7
 
}