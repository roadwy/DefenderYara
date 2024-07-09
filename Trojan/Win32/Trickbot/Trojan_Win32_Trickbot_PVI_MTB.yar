
rule Trojan_Win32_Trickbot_PVI_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53 56 57 50 53 } //2
		$a_02_1 = {58 5b 6a 04 68 00 30 00 00 68 00 e1 f5 05 6a 00 ff 15 ?? ?? ?? ?? 8b c8 50 53 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}