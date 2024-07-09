
rule Backdoor_Win32_Hupigon_DZ{
	meta:
		description = "Backdoor:Win32/Hupigon.DZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {6a 07 8b 45 ?? e8 ?? ?? ?? ?? 50 ff 15 } //2
		$a_00_1 = {8a 03 3c 07 77 07 83 e0 7f } //1
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_3 = {52 65 6d 6f 74 65 20 41 42 43 } //1 Remote ABC
		$a_00_4 = {41 56 50 53 79 74 65 6d 50 69 64 } //1 AVPSytemPid
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}