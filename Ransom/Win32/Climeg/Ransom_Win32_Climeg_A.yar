
rule Ransom_Win32_Climeg_A{
	meta:
		description = "Ransom:Win32/Climeg.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 61 6e 73 6f 6d 5c 63 73 5c 72 61 6e 73 6f 6d 5c 72 61 6e 73 6f 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 61 6e 73 6f 6d 2e 70 64 62 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}