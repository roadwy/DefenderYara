
rule Trojan_Win32_JuiceStealer_G_MSR{
	meta:
		description = "Trojan:Win32/JuiceStealer.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_80_0 = {6d 65 74 61 5c 6d 65 74 61 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6e 65 74 63 6f 72 65 61 70 70 33 2e 31 5c 77 69 6e 2d 78 38 36 5c 6d 65 74 61 2e 70 64 62 } //meta\meta\obj\Release\netcoreapp3.1\win-x86\meta.pdb  5
		$a_80_1 = {43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //Chrome\User Data\Default\Login Data  5
		$a_80_2 = {53 79 73 74 65 6d 2e 4e 65 74 2e 52 65 71 75 65 73 74 73 } //System.Net.Requests  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5) >=15
 
}