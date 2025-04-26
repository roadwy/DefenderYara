
rule PWS_Win32_bot_DL_MTB{
	meta:
		description = "PWS:Win32/bot.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 03 00 00 00 f7 f9 8b 45 e8 0f be 0c 10 8b 95 ?? ?? ?? ?? 0f b6 44 15 f4 33 c1 8b 8d ?? ?? ?? ?? 88 44 0d f4 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}