
rule Trojan_Win64_Manuscrypt_ARAX_MTB{
	meta:
		description = "Trojan:Win64/Manuscrypt.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 74 04 60 3a 48 ff c0 48 3d 8c 0a 00 00 7c f0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}