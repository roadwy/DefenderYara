
rule Trojan_Win32_Danabot_YAB_MTB{
	meta:
		description = "Trojan:Win32/Danabot.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 49 04 31 d2 31 4c 16 10 83 c2 04 39 c2 72 f5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}