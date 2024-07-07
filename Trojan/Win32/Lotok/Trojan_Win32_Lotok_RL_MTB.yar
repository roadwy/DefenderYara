
rule Trojan_Win32_Lotok_RL_MTB{
	meta:
		description = "Trojan:Win32/Lotok.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 14 99 59 f7 f9 6a 00 89 45 e8 8b 46 58 99 f7 f9 89 45 ec ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}