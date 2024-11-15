
rule Trojan_Win32_StealC_EZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e0 ?? 03 45 ?? 33 45 ?? 33 c1 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_EZ_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 03 cb 89 45 ?? 8b 45 ?? 01 45 ?? 8b fb c1 e7 ?? 03 7d ?? 33 f9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_EZ_MTB_3{
	meta:
		description = "Trojan:Win32/StealC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_81_0 = {55 53 45 52 33 32 2e 64 71 6c } //1 USER32.dql
		$a_81_1 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 57 69 6e 64 6f 77 73 20 58 50 20 56 69 73 75 61 6c 20 53 74 79 6c 65 73 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e } //1 <description>Windows XP Visual Styles</description>
		$a_81_2 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //1 %userappdata%\RestartApp.exe
		$a_81_3 = {2e 74 61 67 67 61 6e 74 } //2 .taggant
		$a_81_4 = {54 68 65 6d 69 64 61 } //2 Themida
		$a_81_5 = {48 41 52 44 57 41 52 45 5c 41 43 50 49 5c 44 53 44 54 5c 56 42 4f 58 5f 5f } //1 HARDWARE\ACPI\DSDT\VBOX__
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*1) >=8
 
}