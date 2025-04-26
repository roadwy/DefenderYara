
rule Trojan_Win32_Coroxy_DA_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 89 18 8b 45 cc 03 45 ac 2d ?? ?? ?? ?? 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Coroxy_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Coroxy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 ?? ?? ?? ?? ?? ?? ?? 8b d8 03 5d b4 ?? ?? ?? ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 ?? ?? ?? ?? ?? ?? ?? 8b 55 e8 83 c2 04 03 c2 89 45 e8 ?? ?? ?? ?? ?? ?? ?? 83 c0 04 01 45 ec 8b 45 e8 3b 45 e4 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}