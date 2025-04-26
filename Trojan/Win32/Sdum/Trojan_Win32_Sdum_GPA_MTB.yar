
rule Trojan_Win32_Sdum_GPA_MTB{
	meta:
		description = "Trojan:Win32/Sdum.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 5e f7 f6 8b 45 08 8a 04 02 30 04 19 41 3b cf 72 e9 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}