
rule Trojan_Win32_GuLoader_SIBM1_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 00 20 00 50 00 2e 00 49 00 2e 00 43 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //01 00  % P.I.C Program
		$a_00_1 = {5a 6f 75 61 76 65 35 } //01 00  Zouave5
		$a_03_2 = {b8 00 00 00 00 90 02 0a 50 90 02 6a b8 90 01 04 90 02 f0 01 c2 90 02 6a ff 12 90 02 70 ff 37 90 02 0a 5d 90 02 6a 31 f5 90 02 0a 31 2c 10 90 02 6a 83 c2 04 90 02 0a 83 c7 04 90 02 6a 81 fa 90 01 04 0f 85 90 01 04 90 02 6a 50 90 02 0a c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}