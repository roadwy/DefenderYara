
rule Trojan_Win32_Foosace_I_dha{
	meta:
		description = "Trojan:Win32/Foosace.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 00 00 00 c7 05 90 01 04 2c 00 00 00 c7 05 90 01 04 40 00 00 00 c7 05 90 01 04 f8 00 00 00 90 00 } //01 00 
		$a_00_1 = {67 53 68 61 72 65 64 49 6e 66 6f 00 75 00 73 00 65 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //00 00  卧慨敲䥤普ouser32.dll
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}