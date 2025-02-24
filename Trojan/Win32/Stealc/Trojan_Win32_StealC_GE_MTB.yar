
rule Trojan_Win32_StealC_GE_MTB{
	meta:
		description = "Trojan:Win32/StealC.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {a1 38 74 46 00 8a 8c 30 4b 13 01 00 8b 15 8c 60 46 00 88 0c 32 81 3d fc 65 46 00 90 04 00 00 75 1e } //1
		$a_01_1 = {a1 38 64 45 00 8a 8c 30 4b 13 01 00 8b 15 8c 50 45 00 88 0c 32 81 3d fc 55 45 00 90 04 00 00 75 1e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}