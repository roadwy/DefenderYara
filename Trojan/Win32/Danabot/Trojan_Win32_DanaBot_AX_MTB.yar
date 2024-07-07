
rule Trojan_Win32_DanaBot_AX_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f3 33 75 90 01 01 89 7d 90 01 01 29 75 90 01 01 25 90 01 04 81 6d 90 02 30 bb 90 01 04 81 45 90 02 30 8b 45 90 01 01 8b 4d 90 01 01 8b d0 d3 e2 8b c8 c1 e9 90 01 01 03 4d 90 01 01 03 55 90 01 01 89 3d 90 01 04 33 d1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}