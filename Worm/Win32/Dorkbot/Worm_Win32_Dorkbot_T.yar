
rule Worm_Win32_Dorkbot_T{
	meta:
		description = "Worm:Win32/Dorkbot.T,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 03 46 3c ff b4 30 08 01 00 00 8b 8c 30 0c 01 00 00 8d 84 30 f8 00 00 00 03 ce 51 8b 40 0c 03 43 34 50 ff ?? ?? ff ?? ?? 0f b7 43 06 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}