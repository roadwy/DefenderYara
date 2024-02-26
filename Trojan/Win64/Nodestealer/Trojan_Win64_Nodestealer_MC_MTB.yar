
rule Trojan_Win64_Nodestealer_MC_MTB{
	meta:
		description = "Trojan:Win64/Nodestealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 4f 00 66 00 66 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  MicrosofOffice.exe
	condition:
		any of ($a_*)
 
}