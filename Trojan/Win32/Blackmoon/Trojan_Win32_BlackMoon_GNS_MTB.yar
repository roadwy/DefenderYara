
rule Trojan_Win32_BlackMoon_GNS_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {b4 8d b6 29 33 06 32 d6 89 d1 } //5
		$a_03_1 = {95 32 04 20 83 c3 43 5d 80 30 39 b8 ?? ?? ?? ?? d5 f7 8c a2 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}