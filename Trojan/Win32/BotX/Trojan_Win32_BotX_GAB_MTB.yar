
rule Trojan_Win32_BotX_GAB_MTB{
	meta:
		description = "Trojan:Win32/BotX.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8d 34 19 6a ?? 8b c1 5d f7 f5 80 c2 ?? 32 14 37 41 88 16 83 f9 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}