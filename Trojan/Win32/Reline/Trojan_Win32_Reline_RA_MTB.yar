
rule Trojan_Win32_Reline_RA_MTB{
	meta:
		description = "Trojan:Win32/Reline.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 41 53 66 64 72 74 77 79 65 66 64 65 79 74 77 72 } //01 00  GASfdrtwyefdeytwr
		$a_81_1 = {47 46 41 53 72 74 65 66 64 77 74 72 64 77 65 } //01 00  GFASrtefdwtrdwe
		$a_81_2 = {62 5a 47 74 41 52 59 50 46 5c 41 65 57 47 35 } //01 00  bZGtARYPF\AeWG5
		$a_81_3 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 45 78 } //00 00  GetLocaleInfoEx
	condition:
		any of ($a_*)
 
}