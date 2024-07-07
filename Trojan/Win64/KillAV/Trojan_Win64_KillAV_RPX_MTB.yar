
rule Trojan_Win64_KillAV_RPX_MTB{
	meta:
		description = "Trojan:Win64/KillAV.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 08 56 57 48 81 ec 88 00 00 00 c6 44 24 68 00 48 8d 44 24 69 48 8b f8 33 c0 b9 09 00 00 00 f3 aa 48 8d 44 24 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}