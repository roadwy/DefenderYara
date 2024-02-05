
rule Ransom_Win32_Basta_CB_MTB{
	meta:
		description = "Ransom:Win32/Basta.CB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 8b 0d 30 00 00 00 8b 49 0c } //01 00 
		$a_01_1 = {8b 49 0c 8b 09 } //01 00 
		$a_01_2 = {8d 51 30 8b 12 } //00 00 
	condition:
		any of ($a_*)
 
}