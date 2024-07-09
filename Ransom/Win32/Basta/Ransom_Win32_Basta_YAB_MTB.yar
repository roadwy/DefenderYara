
rule Ransom_Win32_Basta_YAB_MTB{
	meta:
		description = "Ransom:Win32/Basta.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 14 8b 91 ?? ?? ?? ?? 8b 45 f4 8b 4d 14 8b 14 82 33 51 5c 8b 45 14 8b 88 ?? ?? ?? ?? 8b 45 f4 89 14 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}