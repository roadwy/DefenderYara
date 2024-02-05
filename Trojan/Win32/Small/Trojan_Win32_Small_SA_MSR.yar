
rule Trojan_Win32_Small_SA_MSR{
	meta:
		description = "Trojan:Win32/Small.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 74 59 52 4a 54 49 57 4c 69 4f 7a 6b 6d 58 47 58 73 49 74 49 57 6b 52 54 65 53 65 } //01 00 
		$a_01_1 = {51 75 69 74 74 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}