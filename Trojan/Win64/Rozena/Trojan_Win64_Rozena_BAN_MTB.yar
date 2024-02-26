
rule Trojan_Win64_Rozena_BAN_MTB{
	meta:
		description = "Trojan:Win64/Rozena.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {4e 8d 0c 03 4d 39 d0 7d 2c 42 8d 0c 03 42 32 4c 00 10 4c 89 ca 48 c1 fa 08 31 d1 4c 89 ca 49 c1 f9 18 48 c1 fa 10 31 d1 44 31 c9 42 88 4c 00 10 49 ff c0 eb } //00 00 
	condition:
		any of ($a_*)
 
}