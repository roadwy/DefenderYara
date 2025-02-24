
rule Ransom_Win32_Basta_KGQ_MTB{
	meta:
		description = "Ransom:Win32/Basta.KGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 99 f7 fe 8b 45 00 8b 74 24 50 8b 7c 24 58 89 5c 24 20 32 14 30 0f b6 c1 0f b6 ca 0f af c8 a1 ?? ?? ?? ?? 40 a3 ?? ?? ?? ?? 8d 3c 87 } //10
	condition:
		((#a_03_0  & 1)*10) >=5
 
}