
rule Ransom_Win32_Basta_AI_MTB{
	meta:
		description = "Ransom:Win32/Basta.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 08 8b fe 90 13 bb ?? ?? ?? ?? 90 90 90 13 8b 4d ?? fc 90 13 ac 90 90 90 13 02 c3 90 90 90 13 90 90 8b f6 90 13 32 c3 90 90 90 13 fc c0 c8 ?? 90 13 aa fc 90 13 49 90 13 ac 90 90 90 13 02 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}