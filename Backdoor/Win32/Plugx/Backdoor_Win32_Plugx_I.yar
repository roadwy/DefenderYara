
rule Backdoor_Win32_Plugx_I{
	meta:
		description = "Backdoor:Win32/Plugx.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6d 6d 46 75 6e 63 2e 64 6c 6c 00 47 65 74 49 6e 73 74 50 61 74 68 00 48 69 64 65 45 78 65 63 75 74 65 00 } //1
		$a_00_1 = {43 00 6f 00 6d 00 6d 00 46 00 75 00 6e 00 63 00 2e 00 6a 00 61 00 78 00 } //1 CommFunc.jax
		$a_01_2 = {0f b7 45 ec 0f b7 4d ee 6b c0 64 03 c1 0f b7 4d f2 6b c0 64 03 c1 3d 0f 51 33 01 } //1
		$a_03_3 = {68 00 00 00 80 57 ff 15 ?? ?? 00 10 83 f8 ff 74 2f 56 8d 4d fc 51 53 57 50 ff 15 ?? ?? 00 10 85 c0 74 1d 53 56 57 6a 00 ff 55 ?? 5f 5e 5f 8b 35 ?? ?? 00 10 6a ff ff d6 6a ff ff d6 6a ff ff d6 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}