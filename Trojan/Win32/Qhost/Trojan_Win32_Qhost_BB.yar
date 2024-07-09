
rule Trojan_Win32_Qhost_BB{
	meta:
		description = "Trojan:Win32/Qhost.BB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //2 C:\WINDOWS\system32\drivers\etc\hosts
		$a_02_1 = {64 61 74 61 5c [0-08] 2e 64 6c 6c 90 05 04 01 00 63 72 6f 73 73 66 69 72 65 2e 65 78 65 } //2
		$a_00_2 = {5c 64 33 64 39 2e 64 6c 6c } //1 \d3d9.dll
		$a_00_3 = {5c 64 33 64 78 39 5f 33 37 2e 64 6c 6c } //1 \d3dx9_37.dll
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}