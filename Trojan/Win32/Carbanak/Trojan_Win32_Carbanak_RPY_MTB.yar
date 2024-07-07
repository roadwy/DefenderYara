
rule Trojan_Win32_Carbanak_RPY_MTB{
	meta:
		description = "Trojan:Win32/Carbanak.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 83 c8 01 0f af c7 29 c1 89 c8 99 f7 7d e4 89 d7 8b 75 ec 8b 55 f0 8a 04 16 8a 4d e3 d2 e0 8a 0c 3e 88 0c 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}