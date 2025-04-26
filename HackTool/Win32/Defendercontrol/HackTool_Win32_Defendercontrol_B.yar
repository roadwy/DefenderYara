
rule HackTool_Win32_Defendercontrol_B{
	meta:
		description = "HackTool:Win32/Defendercontrol.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 6f 72 64 75 6d 20 53 6f 66 74 77 61 72 65 } //Sordum Software  1
		$a_80_1 = {55 6e 69 7a 65 74 6f 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 } //Unizeto Technologies  1
		$a_80_2 = {55 50 58 30 } //UPX0  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}