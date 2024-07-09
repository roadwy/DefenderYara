
rule Trojan_Win32_Trickbot_DHF_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 ff 75 b0 53 ff 55 c4 ff 75 b0 89 45 d0 ff 75 ac 50 e8 ?? ?? ?? ?? 57 6a ?? 68 ?? ?? ?? ?? ff 75 a8 56 ff 55 d0 83 c4 20 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}