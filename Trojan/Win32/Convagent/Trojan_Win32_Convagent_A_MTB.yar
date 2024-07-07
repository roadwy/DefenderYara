
rule Trojan_Win32_Convagent_A_MTB{
	meta:
		description = "Trojan:Win32/Convagent.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 5d a0 d0 66 f7 a4 24 80 00 00 00 8b 84 24 80 00 00 00 81 ac 24 80 00 00 00 d6 8a cd 68 b8 e2 3f 96 6e f7 a4 24 80 00 00 00 8b 84 24 80 00 00 00 81 84 24 80 00 00 00 86 7c 61 60 8a 84 37 3b 2d 0b 00 88 04 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}