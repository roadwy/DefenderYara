
rule Ransom_Win32_Basta_KTS_MTB{
	meta:
		description = "Ransom:Win32/Basta.KTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f7 8b 44 24 14 31 14 98 33 d2 a1 ?? ?? ?? ?? f7 f3 0f b7 05 ?? ?? ?? ?? 03 d0 8b 44 24 5c 0f b7 44 68 06 8b 6c 24 10 23 d0 8b 44 24 50 0f af 14 88 89 14 88 41 3b 4c 24 40 7f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}