
rule Trojan_Win64_ReflectiveLoader_EM_MTB{
	meta:
		description = "Trojan:Win64/ReflectiveLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 8d 3c 3a 49 83 c7 28 48 89 d6 48 01 fe 4c 89 7c 24 78 89 9c 24 80 00 00 00 48 89 4c 24 58 48 8d 04 31 48 83 c0 28 48 89 44 24 50 48 89 84 24 88 00 00 00 44 89 b4 24 90 00 00 00 48 8d 9c 24 98 00 00 00 48 c7 03 00 00 00 00 48 89 5c 24 20 } //00 00 
	condition:
		any of ($a_*)
 
}