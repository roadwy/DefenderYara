
rule Backdoor_Win32_Mate_NK_MTB{
	meta:
		description = "Backdoor:Win32/Mate.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 07 00 ff 15 c4 30 41 00 8b f0 85 f6 0f 84 83 00 00 00 8b 45 04 56 50 ff 15 c0 30 41 00 8b d8 8b 45 04 56 50 ff 15 bc 30 41 00 8b f0 85 f6 89 74 24 10 74 61 56 ff 15 b8 30 41 00 8a 4c 18 ff 84 c9 74 35 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}