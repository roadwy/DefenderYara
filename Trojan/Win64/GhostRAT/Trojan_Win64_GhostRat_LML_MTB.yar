
rule Trojan_Win64_GhostRat_LML_MTB{
	meta:
		description = "Trojan:Win64/GhostRat.LML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 54 11 01 80 30 a7 48 83 c0 01 48 39 d0 75 f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}