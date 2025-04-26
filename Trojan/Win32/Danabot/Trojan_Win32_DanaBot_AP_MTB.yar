
rule Trojan_Win32_DanaBot_AP_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c8 03 bc 24 [0-30] 0f 57 c0 81 3d [0-30] 66 0f 13 05 [0-30] 89 4c 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}