
rule Trojan_Win64_Mikey_AMBC_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 39 c7 74 ?? 8a 4c 05 d0 41 30 4c 05 00 48 ff c0 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}