
rule Trojan_Win32_Nanobot_RPU_MTB{
	meta:
		description = "Trojan:Win32/Nanobot.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 53 83 c3 27 03 c3 33 c0 bb 26 00 00 00 2b d8 33 db 33 c3 2b d8 33 db 83 eb 1e 2b d8 33 c0 81 c3 97 00 00 00 58 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}