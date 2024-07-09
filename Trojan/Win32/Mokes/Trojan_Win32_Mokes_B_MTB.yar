
rule Trojan_Win32_Mokes_B_MTB{
	meta:
		description = "Trojan:Win32/Mokes.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 1c 76 00 2e 00 [0-09] c7 44 24 ?? 7a 00 67 00 [0-09] c7 44 24 ?? 65 00 76 00 c7 44 24 ?? 2f 00 25 00 c7 44 24 ?? 64 00 2e 00 c7 44 24 ?? 6d 00 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}