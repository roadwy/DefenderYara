
rule Trojan_Win32_Kesmod_A{
	meta:
		description = "Trojan:Win32/Kesmod.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 02 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 3c 53 56 68 20 00 01 00 68 ?? ?? ?? ?? 57 ff 15 } //1
		$a_00_1 = {8b 55 fc 8d 4d f8 51 6a 04 52 6a 0b ff d6 3d 04 00 00 c0 0f 85 dc 00 00 00 8b 45 f8 50 6a 40 ff 15 } //1
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}