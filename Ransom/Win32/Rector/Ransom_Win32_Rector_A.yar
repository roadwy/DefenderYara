
rule Ransom_Win32_Rector_A{
	meta:
		description = "Ransom:Win32/Rector.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {24 26 25 30 34 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 31 00 31 00 30 00 31 00 40 24 26 25 30 34 5c 90 02 0f 2e 65 78 65 00 00 31 00 31 00 30 00 52 75 73 73 69 61 6e 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}