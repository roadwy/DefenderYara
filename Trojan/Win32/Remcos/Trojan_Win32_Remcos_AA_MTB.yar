
rule Trojan_Win32_Remcos_AA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 64 76 54 5f 69 31 6a 73 6f 33 76 37 4d 74 57 30 2f 65 73 2e 75 75 67 75 2e 61 2f 2f 3a 73 70 74 74 68 } //00 00  zdvT_i1jso3v7MtW0/es.uugu.a//:sptth
	condition:
		any of ($a_*)
 
}