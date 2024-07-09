
rule Trojan_Win64_DCRat_D_MTB{
	meta:
		description = "Trojan:Win64/DCRat.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c1 8b 45 ?? 48 0f be 11 48 8d 0d ?? ?? ?? ?? 0f be 0c 11 c1 f9 ?? 83 e1 ?? 09 c8 88 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}