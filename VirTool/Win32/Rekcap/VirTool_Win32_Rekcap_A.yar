
rule VirTool_Win32_Rekcap_A{
	meta:
		description = "VirTool:Win32/Rekcap.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 8b 90 01 05 a3 90 01 04 a1 90 01 04 33 90 01 01 89 90 01 05 85 c0 76 90 02 10 8b 90 01 05 8a 90 01 06 8b 90 01 05 88 90 02 10 a1 90 02 0b 3b 90 01 01 72 90 00 } //01 00 
		$a_03_1 = {6a 40 51 52 a3 90 01 04 ff d0 90 0a 50 00 68 90 01 04 68 90 01 04 ff 15 90 01 04 68 90 01 04 ff 15 90 01 04 68 90 01 04 50 ff 15 90 01 04 8b 0d 90 01 04 8d 90 02 05 52 8b 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}