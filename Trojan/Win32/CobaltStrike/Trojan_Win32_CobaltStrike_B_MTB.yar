
rule Trojan_Win32_CobaltStrike_B_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 ac c1 c7 ?? 03 f8 3c ?? 75 ?? 39 7c 24 08 75 } //2
		$a_01_1 = {49 8b 34 8a 03 f3 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}