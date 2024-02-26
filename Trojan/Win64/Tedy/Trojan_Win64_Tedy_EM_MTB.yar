
rule Trojan_Win64_Tedy_EM_MTB{
	meta:
		description = "Trojan:Win64/Tedy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {30 84 0d 18 05 00 00 48 ff c1 48 83 f9 25 72 ed } //00 00 
	condition:
		any of ($a_*)
 
}