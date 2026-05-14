
rule Trojan_Win32_Amadey_PGAE_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PGAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 2b 82 fe 1a 8c 15 24 c8 5e 98 f8 8b 56 36 70 38 34 61 b0 cf 4b e5 99 bd 2e 26 35 3b 7d 41 32 2b f9 3a a8 27 56 97 a0 a6 98 2f de ed 57 3c d1 3d ac 32 8c 15 24 c8 06 15 10 82 06 a9 70 88 24 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}