
rule Virus_Win32_Glacid_A{
	meta:
		description = "Virus:Win32/Glacid.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 69 67 6c 69 63 64 36 34 2e 64 6c } //00 00  \iglicd64.dl
	condition:
		any of ($a_*)
 
}