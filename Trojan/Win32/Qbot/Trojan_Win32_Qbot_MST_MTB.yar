
rule Trojan_Win32_Qbot_MST_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 83 c1 04 89 4d fc e8 ?? ?? ?? ?? ba 39 00 00 00 85 d2 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}