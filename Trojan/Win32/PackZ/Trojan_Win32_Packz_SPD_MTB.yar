
rule Trojan_Win32_Packz_SPD_MTB{
	meta:
		description = "Trojan:Win32/Packz.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {8b 32 81 c7 49 09 60 7e b9 78 c6 9c 1b 81 e6 ff 00 00 00 21 c0 81 c7 bb 9b ba 78 31 33 01 f9 09 cf b8 37 aa 6c d4 81 c3 01 00 00 00 81 c1 01 00 00 00 21 c1 b9 82 7b b5 73 42 29 c1 40 81 fb 92 9c 65 00 0f 8c b7 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}