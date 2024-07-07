
rule Trojan_Win32_Convagent_VW_MTB{
	meta:
		description = "Trojan:Win32/Convagent.VW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 83 25 24 4d 46 00 00 33 c3 2b f8 89 7d e0 8b 45 d4 29 45 fc ff 4d e4 0f 85 90 01 04 8b 45 e8 89 3e 5f 89 46 04 5e 5b 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}