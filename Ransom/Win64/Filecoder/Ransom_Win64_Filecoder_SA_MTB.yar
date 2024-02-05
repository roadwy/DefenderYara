
rule Ransom_Win64_Filecoder_SA_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 45 d8 0f b6 00 83 f0 15 89 c2 48 8b 45 d8 88 10 48 83 45 d8 01 83 45 d4 01 8b 45 d4 3b 45 bc 7c } //00 00 
	condition:
		any of ($a_*)
 
}