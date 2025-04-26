
rule Worm_Win32_Braban_B{
	meta:
		description = "Worm:Win32/Braban.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 8b 45 fc e8 ?? ?? ?? ?? 8b f0 85 f6 7e 2c bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 81 ea 06 12 0f 00 e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 d9 8b c7 8b 55 f8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}