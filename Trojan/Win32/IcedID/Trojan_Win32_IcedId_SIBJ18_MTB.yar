
rule Trojan_Win32_IcedId_SIBJ18_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ18!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 61 70 70 65 6e 2e 70 64 62 } //01 00  Happen.pdb
		$a_03_1 = {83 c7 04 81 ff 90 01 04 90 02 10 90 18 90 02 60 8b 2d 90 01 04 90 02 20 8b b4 2f 90 01 04 90 02 30 81 c6 d0 10 08 01 89 b4 2f 90 01 04 83 c7 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}