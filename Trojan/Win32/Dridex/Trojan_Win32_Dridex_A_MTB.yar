
rule Trojan_Win32_Dridex_A_MTB{
	meta:
		description = "Trojan:Win32/Dridex.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 54 24 6b 8b 5c 24 38 8b 54 24 1c 8a 04 1a 8b 54 24 50 69 d2 [0-04] 01 f1 21 f9 89 54 24 50 8b 54 24 14 8a 24 0a 30 c4 31 c9 89 4c 24 5c c7 44 24 58 6b 0a f2 61 8b 74 24 18 88 24 1e 8b 7c 24 58 81 e7 bf 89 6f 54 8b 5c 24 38 43 } //1
		$a_00_1 = {88 5c 24 77 8b 54 24 44 66 c7 44 24 66 0a fb 8b 74 24 44 8b 7c 24 2c 8a 1c 17 8b 54 24 24 32 1c 02 8b 44 24 28 88 1c 30 8b 74 24 48 8b 44 24 44 83 c0 01 8a 5c 24 23 80 cb ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}