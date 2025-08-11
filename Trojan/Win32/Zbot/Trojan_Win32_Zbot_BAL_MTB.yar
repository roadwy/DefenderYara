
rule Trojan_Win32_Zbot_BAL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f dc db 0f 60 f1 66 0f e9 d3 31 37 0f e5 ed } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}