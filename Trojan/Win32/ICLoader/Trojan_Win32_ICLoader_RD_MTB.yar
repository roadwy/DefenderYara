
rule Trojan_Win32_ICLoader_RD_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 57 8b 3d 78 01 65 00 68 7c 32 65 00 ff d7 8b 35 74 01 65 00 a3 70 41 a5 00 85 c0 0f 84 ff 00 00 00 68 64 32 65 00 50 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ICLoader_RD_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {d0 16 66 00 83 c4 04 03 ?? 89 ?? d0 16 66 00 e8 ?? ?? 00 00 e9 } //5
		$a_01_1 = {62 00 75 00 72 00 6e 00 69 00 6e 00 67 00 73 00 74 00 75 00 64 00 69 00 6f 00 2e 00 65 00 78 00 65 00 } //1 burningstudio.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_ICLoader_RD_MTB_3{
	meta:
		description = "Trojan:Win32/ICLoader.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 5e 5b 5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 57 e9 } //1
		$a_01_1 = {43 00 6f 00 72 00 74 00 65 00 78 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //1 CortexLauncherService.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}