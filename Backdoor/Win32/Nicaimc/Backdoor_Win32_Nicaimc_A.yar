
rule Backdoor_Win32_Nicaimc_A{
	meta:
		description = "Backdoor:Win32/Nicaimc.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 4c 4c 49 4f 54 41 4c 44 45 52 53 4f 4e 54 59 52 45 4c 4c 57 45 4c 4c 49 43 4b } //2 ELLIOTALDERSONTYRELLWELLICK
		$a_01_1 = {41 70 70 43 6f 6e 74 61 69 6e 65 72 44 62 67 2e 63 72 74 } //1 AppContainerDbg.crt
		$a_01_2 = {47 6c 6f 62 61 6c 5c 43 4d 49 41 43 49 4e } //1 Global\CMIACIN
		$a_03_3 = {be 11 00 00 00 f7 fe 0f ?? ?? ?? ?? 33 ca 8b 45 08 03 45 fc 88 08 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}