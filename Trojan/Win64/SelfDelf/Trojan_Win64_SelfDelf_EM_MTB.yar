
rule Trojan_Win64_SelfDelf_EM_MTB{
	meta:
		description = "Trojan:Win64/SelfDelf.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {b8 00 00 eb 06 4d 31 d2 4d 31 db 43 8a 04 18 42 30 04 11 49 ff c2 49 ff c3 49 39 d2 74 0d 45 38 cb 74 02 } //00 00 
	condition:
		any of ($a_*)
 
}