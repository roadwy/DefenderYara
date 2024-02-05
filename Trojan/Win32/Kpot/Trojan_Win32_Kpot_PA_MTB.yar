
rule Trojan_Win32_Kpot_PA_MTB{
	meta:
		description = "Trojan:Win32/Kpot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 02 88 45 ff b0 90 01 01 8a 5d ff 32 c3 8b 7d f8 03 7d f4 88 07 ff 45 f4 42 81 7d f4 90 01 02 00 00 75 90 00 } //01 00 
		$a_00_1 = {31 db 8b 04 8a 88 c7 88 e3 c1 e8 10 c1 e3 08 88 c3 89 1c 8a 49 79 } //00 00 
	condition:
		any of ($a_*)
 
}