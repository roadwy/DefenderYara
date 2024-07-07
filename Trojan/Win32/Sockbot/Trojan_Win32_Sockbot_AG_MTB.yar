
rule Trojan_Win32_Sockbot_AG_MTB{
	meta:
		description = "Trojan:Win32/Sockbot.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 0c 3e 46 3b f3 7c cb 5d 5e 81 fb 71 11 00 00 75 14 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}