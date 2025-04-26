
rule Trojan_Win32_Gandcrab_S_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {27 64 6c 6c 3a 3a 4e 74 43 27 2c 74 20 27 72 65 61 74 27 2c 20 74 20 27 65 53 65 63 74 27 2c 74 27 69 6f 6e 28 70 20 20 72 32 2c 69 20 27 2c 20 69 20 20 30 78 45 2c 74 20 27 2c 6e 2c 27 29 } //1 'dll::NtC',t 'reat', t 'eSect',t'ion(p  r2,i ', i  0xE,t ',n,')
		$a_01_1 = {6e 74 64 6c 6c 3a 3a 4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 28 70 } //1 ntdll::NtMapViewOfSection(p
		$a_01_2 = {6b 65 72 6e 65 6c 33 32 3a 3a 43 6c 6f 73 65 48 61 6e 64 6c 65 28 69 } //1 kernel32::CloseHandle(i
		$a_01_3 = {6b 65 72 6e 65 6c 33 32 3a 3a 43 72 65 61 74 65 46 69 6c 65 28 70 } //1 kernel32::CreateFile(p
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}