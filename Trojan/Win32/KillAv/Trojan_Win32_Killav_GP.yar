
rule Trojan_Win32_Killav_GP{
	meta:
		description = "Trojan:Win32/Killav.GP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 } //1 GbPlugin\
		$a_03_1 = {30 39 2e 3a 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 70 72 69 6e 63 69 70 61 6c } //1
		$a_00_2 = {61 00 76 00 67 00 6e 00 73 00 78 00 2e 00 65 00 78 00 65 00 } //1 avgnsx.exe
		$a_00_3 = {41 00 56 00 47 00 4e 00 54 00 } //1 AVGNT
		$a_00_4 = {53 65 72 76 69 63 65 41 66 74 65 72 49 6e 73 74 61 6c 6c } //1 ServiceAfterInstall
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}