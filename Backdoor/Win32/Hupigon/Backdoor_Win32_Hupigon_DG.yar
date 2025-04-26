
rule Backdoor_Win32_Hupigon_DG{
	meta:
		description = "Backdoor:Win32/Hupigon.DG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6d 64 30 30 31 00 00 ff ff ff ff 06 00 00 00 43 6d 64 30 30 32 00 } //1
		$a_00_1 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 00 } //1
		$a_03_2 = {8b f0 89 35 ?? ?? ?? ?? 85 f6 74 0e 6a 01 e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 33 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}