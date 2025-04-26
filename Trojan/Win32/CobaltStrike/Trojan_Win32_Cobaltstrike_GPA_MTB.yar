
rule Trojan_Win32_Cobaltstrike_GPA_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 89 45 e8 33 d2 85 db 74 26 8b 75 e0 8b f8 90 8b c2 8b ca c1 e8 02 83 e1 03 c1 e1 03 8b 04 86 d3 e8 88 04 3a 42 3b d3 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}