
rule VirTool_Win32_Meterpreter_J_MTB{
	meta:
		description = "VirTool:Win32/Meterpreter.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 0e 20 85 c0 84 84 46 02 00 00 6a 99 ff 90 01 01 83 c4 3d 33 c0 90 00 } //1
		$a_00_1 = {83 c4 04 01 c0 d0 13 8b 4d 10 8b ca 8c 50 51 52 } //1
		$a_00_2 = {21 43 50 a4 f8 73 09 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}