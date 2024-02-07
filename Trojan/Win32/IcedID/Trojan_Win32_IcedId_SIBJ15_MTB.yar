
rule Trojan_Win32_IcedId_SIBJ15_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ15!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 69 00 6e 00 67 00 6c 00 65 00 67 00 6f 00 6f 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  singlegood.exe
		$a_03_1 = {8b 44 24 10 90 01 04 90 02 50 8b 44 24 10 90 02 10 83 44 24 10 04 81 c7 90 01 04 89 38 90 02 20 ff 4c 24 90 01 01 90 02 10 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}