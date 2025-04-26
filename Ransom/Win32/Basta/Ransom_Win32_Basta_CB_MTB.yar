
rule Ransom_Win32_Basta_CB_MTB{
	meta:
		description = "Ransom:Win32/Basta.CB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 8b 0d 30 00 00 00 8b 49 0c } //1
		$a_01_1 = {8b 49 0c 8b 09 } //1
		$a_01_2 = {8d 51 30 8b 12 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}