
rule PWS_Win32_Zbot_ZT{
	meta:
		description = "PWS:Win32/Zbot.ZT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 c0 74 68 80 7c 24 0f e9 75 61 8d 44 24 10 50 68 60 63 f1 78 68 } //01 00 
		$a_01_1 = {83 7c 24 10 0c 0f 85 f0 01 00 00 6a 02 68 7b 34 89 87 e8 } //01 00 
		$a_01_2 = {84 c0 0f 84 44 03 00 00 33 db 43 53 8d 44 24 34 50 68 30 11 90 38 e8 } //00 00 
	condition:
		any of ($a_*)
 
}