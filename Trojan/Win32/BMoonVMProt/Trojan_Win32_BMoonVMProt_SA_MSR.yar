
rule Trojan_Win32_BMoonVMProt_SA_MSR{
	meta:
		description = "Trojan:Win32/BMoonVMProt.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 55 63 6b 54 65 6e 74 63 74 } //01 00 
		$a_01_1 = {67 67 2e 69 6e 69 } //01 00 
		$a_01_2 = {64 6e 66 2e 65 78 65 } //01 00 
		$a_01_3 = {42 67 2e 63 6d 64 } //00 00 
	condition:
		any of ($a_*)
 
}