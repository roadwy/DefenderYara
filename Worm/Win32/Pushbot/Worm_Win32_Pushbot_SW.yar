
rule Worm_Win32_Pushbot_SW{
	meta:
		description = "Worm:Win32/Pushbot.SW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f b6 1c 08 0f b6 14 0a 01 d3 89 da 81 e2 00 03 00 00 29 d3 0f b6 04 19 30 04 3e 46 } //1
		$a_01_1 = {6e 65 74 20 73 74 6f 70 20 4d 73 4d 70 53 76 63 } //1 net stop MsMpSvc
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}