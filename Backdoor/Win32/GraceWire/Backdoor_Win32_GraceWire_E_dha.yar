
rule Backdoor_Win32_GraceWire_E_dha{
	meta:
		description = "Backdoor:Win32/GraceWire.E!dha,SIGNATURE_TYPE_PEHSTR,ffffffe8 03 ffffffe8 03 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 33 6f 65 43 53 49 66 78 30 4a 36 55 74 63 56 } //01 00  c3oeCSIfx0J6UtcV
		$a_01_1 = {65 72 30 65 77 6a 66 6c 6b 33 71 72 68 6a 38 31 } //00 00  er0ewjflk3qrhj81
	condition:
		any of ($a_*)
 
}