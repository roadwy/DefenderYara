
rule Trojan_Win32_GameThief_SIB_MTB{
	meta:
		description = "Trojan:Win32/GameThief.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f1 33 d2 90 02 10 8a 0f 90 02 10 8a 06 90 18 46 47 80 7d 08 90 01 01 90 18 88 4d 90 01 01 0f 84 90 01 04 8a ca c0 cf 90 01 01 bb 90 01 04 d3 c3 8a 4d 90 1b 05 90 02 10 02 da 90 18 32 c3 90 18 42 90 02 10 84 c0 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}