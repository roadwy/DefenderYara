
rule Trojan_Win32_Trickbot_GGL_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {04 70 30 3f a0 ?? ?? ?? ?? 23 22 c4 00 30 0d ?? ?? ?? ?? e6 8c 02 e4 6d 12 11 48 38 21 40 73 bc } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}