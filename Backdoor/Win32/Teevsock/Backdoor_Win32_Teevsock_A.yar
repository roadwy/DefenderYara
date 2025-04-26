
rule Backdoor_Win32_Teevsock_A{
	meta:
		description = "Backdoor:Win32/Teevsock.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 08 8b 55 ?? 03 55 ?? 33 ca 8b 45 ?? 03 45 ?? 88 08 83 7d ?? 03 7e } //1
		$a_03_1 = {68 e3 07 72 41 68 5d 52 2a 90 90 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 fc 83 7d fc 57 } //1
		$a_00_2 = {73 71 6c 77 69 64 2e 64 6c 6c 00 00 73 76 63 68 6f 73 74 2e 65 78 65 00 73 71 6c 73 72 76 2e 65 78 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}