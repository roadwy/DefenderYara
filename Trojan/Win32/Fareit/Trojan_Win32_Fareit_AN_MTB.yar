
rule Trojan_Win32_Fareit_AN_MTB{
	meta:
		description = "Trojan:Win32/Fareit.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e c6 [0-10] 66 0f 6e c9 [0-10] 66 0f 57 c8 [0-10] 66 0f 7e c9 [0-10] 39 c1 75 ?? [0-20] b8 ?? ?? ?? ?? [0-15] 05 [0-15] 8b 00 [0-15] 68 ?? ?? ?? ?? [0-15] 5b [0-15] 81 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}