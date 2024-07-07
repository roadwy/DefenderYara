
rule Trojan_Win32_Astaroth_psyH_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 08 83 c0 01 39 d0 75 f7 89 f0 89 1c 24 c7 44 24 14 00 a0 05 00 88 44 24 10 8b 84 24 30 a0 05 00 89 44 24 18 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}