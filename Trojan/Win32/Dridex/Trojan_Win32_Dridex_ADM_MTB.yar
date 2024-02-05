
rule Trojan_Win32_Dridex_ADM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {46 46 52 67 70 6d 64 6c 77 77 57 64 65 } //FFRgpmdlwwWde  03 00 
		$a_80_1 = {72 70 69 64 65 62 62 66 6c 6c 2e 70 64 62 } //rpidebbfll.pdb  03 00 
		$a_80_2 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  03 00 
		$a_80_3 = {53 48 47 65 74 44 65 73 6b 74 6f 70 46 6f 6c 64 65 72 } //SHGetDesktopFolder  03 00 
		$a_80_4 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  03 00 
		$a_80_5 = {53 65 74 75 70 44 69 45 6e 75 6d 44 65 76 69 63 65 49 6e 66 6f } //SetupDiEnumDeviceInfo  03 00 
		$a_80_6 = {68 68 6f 6f 65 77 64 61 71 73 78 } //hhooewdaqsx  00 00 
	condition:
		any of ($a_*)
 
}