
rule PWS_Win32_Zbot_AX{
	meta:
		description = "PWS:Win32/Zbot.AX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 31 f1 68 88 a6 02 00 5e 3b f0 75 96 81 f0 13 2c 40 00 75 06 81 f7 44 1e 40 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}