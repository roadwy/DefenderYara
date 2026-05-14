
rule Trojan_Win64_QatarRat_AQA_MTB{
	meta:
		description = "Trojan:Win64/QatarRat.AQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d a8 57 01 00 48 8b f8 48 8b f1 b9 3d 00 00 00 f3 a4 48 8d 84 24 ?? ?? ?? ?? 48 8b f8 33 c0 b9 c3 01 00 00 f3 aa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}