
rule Backdoor_Win32_Remcos_PA_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 30 eb 90 01 01 90 02 20 80 f3 58 eb 90 01 01 90 02 20 f6 d3 eb 90 01 01 90 02 20 80 f3 13 eb 90 01 01 90 02 20 88 1c 30 eb 90 01 01 90 02 20 46 eb 0f 90 02 20 81 fe 90 01 02 00 00 eb 90 01 01 90 02 20 0f 85 90 01 02 ff ff eb 90 00 } //1
		$a_02_1 = {6a 40 68 00 90 01 01 00 00 68 90 01 04 ff 15 90 00 } //1
		$a_00_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}