
rule Trojan_Win32_Convagent_MGZ_MTB{
	meta:
		description = "Trojan:Win32/Convagent.MGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 24 8b 4c 24 3c 8b 74 24 30 03 0a 0f b6 06 30 01 8b c2 8b 4c 24 2c 2b ca 83 e1 fc 81 f9 00 10 00 00 72 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}