
rule Ransom_Win32_Bitpaymer_SIB_MTB{
	meta:
		description = "Ransom:Win32/Bitpaymer.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d0 31 f6 89 54 24 ?? 89 f2 f7 f1 8b 4c 24 ?? 31 c9 89 4c 24 ?? 8b 4c 24 ?? 8b 74 24 ?? 8b 7c 24 90 1b 00 8a 1c 3e 2a 1c 15 ?? ?? ?? ?? c7 44 24 90 1b 02 ?? ?? ?? ?? 8b 54 24 ?? 29 ca 8b 4c 24 ?? 88 1c 39 01 d7 89 7c 24 ?? 8b 54 24 90 1b 01 39 d7 72 } //1
		$a_03_1 = {8b 45 10 8b 4d 0c 8b 55 08 31 f6 c7 44 24 ?? ?? ?? ?? ?? 83 f8 00 89 44 24 ?? 89 4c 24 ?? 89 54 24 ?? 89 74 24 ?? 74 ?? 8b 44 24 90 1b 05 8b 4c 24 90 1b 00 ba 0a 9c 2c 41 29 ca 8b 4c 24 90 1b 03 8a 1c 01 [0-15] 8b 74 24 90 1b 04 88 1c 06 [0-10] 01 d0 [0-0a] 8b 4c 24 90 1b 02 39 c8 89 44 24 90 1b 05 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}