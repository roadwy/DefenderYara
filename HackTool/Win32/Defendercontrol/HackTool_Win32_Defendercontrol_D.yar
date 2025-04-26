
rule HackTool_Win32_Defendercontrol_D{
	meta:
		description = "HackTool:Win32/Defendercontrol.D,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {2f 00 54 00 49 00 20 00 } //1 /TI 
	condition:
		((#a_00_0  & 1)*1) >=1
 
}