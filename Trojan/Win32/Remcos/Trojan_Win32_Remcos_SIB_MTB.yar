
rule Trojan_Win32_Remcos_SIB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 5c 00 41 00 4c 00 41 00 2e 00 44 00 4c 00 4c 00 } //1 C:\\ALA.DLL
		$a_03_1 = {ba 01 00 00 00 a1 90 01 04 8b 38 ff 57 90 01 01 8b 45 90 01 01 8b 16 0f b6 7c 10 90 01 01 a1 90 01 04 e8 90 01 04 ba 00 01 00 00 2b d0 52 a1 90 01 04 e8 90 01 04 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 45 90 01 01 e8 90 01 04 8b 55 90 1b 08 b8 90 01 04 e8 90 01 04 ff 06 ff 4d 90 01 01 75 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}