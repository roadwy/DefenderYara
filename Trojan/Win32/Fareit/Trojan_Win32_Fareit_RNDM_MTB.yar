
rule Trojan_Win32_Fareit_RNDM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RNDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 64 35 66 75 6e 00 00 67 7a 69 70 44 65 63 6f 6d } //01 00 
		$a_01_1 = {d2 43 00 e4 ad 43 00 1c a4 43 00 70 af 43 00 90 3d 45 00 5c 3c 45 00 a8 b0 43 00 08 3e 45 00 50 d3 } //00 00 
	condition:
		any of ($a_*)
 
}