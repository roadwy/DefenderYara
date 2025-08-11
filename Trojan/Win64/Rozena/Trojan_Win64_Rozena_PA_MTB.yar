
rule Trojan_Win64_Rozena_PA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 8b d7 48 8b c1 48 8d 5b 01 83 e0 03 48 ff c1 0f b6 44 04 38 30 43 ff 48 83 ea 01 75 ?? 48 8b 5c 24 ?? 48 83 c4 20 5f c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}