
rule Trojan_Win64_Zusy_SXO_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c1 41 88 84 15 ec fc ff ff 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 42 83 fa 11 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}