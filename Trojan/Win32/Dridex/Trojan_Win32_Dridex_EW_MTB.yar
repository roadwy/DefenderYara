
rule Trojan_Win32_Dridex_EW_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 54 24 03 30 d2 8a 34 01 88 54 24 1b a1 90 01 04 8b 4c 24 30 88 34 08 eb ac 90 00 } //10
		$a_00_1 = {8b 44 24 30 83 c0 01 8b 4c 24 14 01 c9 89 4c 24 1c 89 44 24 30 eb c5 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}