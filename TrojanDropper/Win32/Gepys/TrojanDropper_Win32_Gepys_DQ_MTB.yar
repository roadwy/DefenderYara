
rule TrojanDropper_Win32_Gepys_DQ_MTB{
	meta:
		description = "TrojanDropper:Win32/Gepys.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 45 f8 40 3b 75 f8 7e 9a 8b 55 dc 03 55 fc 8a 12 30 da ff 45 fc e9 } //1
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}