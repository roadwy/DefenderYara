
rule Trojan_Win32_Tinba_RL_MTB{
	meta:
		description = "Trojan:Win32/Tinba.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 0c 0a 89 45 90 01 01 89 4d 90 01 01 8b 45 90 01 01 0f af 45 90 01 01 8b 4d 90 01 01 8b 95 90 01 04 89 8d 90 01 04 89 d1 8b b5 90 01 04 d3 ee 01 f0 8b 75 90 01 01 01 c6 66 8b 7d 90 01 01 66 81 e7 90 01 02 66 89 7d 90 01 01 89 75 90 01 01 8d 45 90 01 01 66 8b 4d 90 01 01 66 89 c2 66 09 d1 66 89 4d 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}