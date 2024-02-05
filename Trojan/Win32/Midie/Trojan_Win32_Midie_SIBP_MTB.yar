
rule Trojan_Win32_Midie_SIBP_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6b 78 6c 73 7a 71 6e 2e 64 6c 6c } //01 00 
		$a_03_1 = {52 6a 40 68 90 01 04 8d 85 90 01 04 50 ff 15 90 01 04 b9 00 00 00 00 8a 84 0d 90 1b 01 81 f9 90 1b 00 74 90 01 01 90 02 08 04 90 01 01 34 90 01 01 90 02 08 04 f7 90 02 08 88 84 0d 90 1b 01 83 c1 01 90 18 8a 84 0d 90 1b 01 81 f9 90 1b 00 90 18 b0 00 b9 00 00 00 00 8d 8d 90 1b 01 ff d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}