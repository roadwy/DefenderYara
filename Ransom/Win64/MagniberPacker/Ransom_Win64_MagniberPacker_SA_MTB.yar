
rule Ransom_Win64_MagniberPacker_SA_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8c 10 88 50 ab 02 1f be ?? ?? ?? ?? 02 53 ?? ed 69 24 ab ?? ?? ?? ?? e7 ?? b5 ?? 30 52 ?? 38 1e 31 67 ?? 7e ?? d1 c8 b4 ?? ef b6 ?? fa b9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}