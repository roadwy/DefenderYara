
rule Trojan_Win32_Citadel_B_MTB{
	meta:
		description = "Trojan:Win32/Citadel.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 18 00 51 40 00 c7 44 24 1c fc 50 40 00 c7 44 24 20 f8 50 40 00 c7 44 24 24 f4 50 40 00 c7 44 24 28 f0 50 40 00 c7 44 24 2c ec 50 40 00 c7 44 24 30 e8 50 40 00 c7 44 24 34 e4 50 40 00 c7 44 24 38 e0 50 40 00 c7 44 24 3c dc 50 40 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}