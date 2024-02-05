
rule Trojan_Win64_Emotetcrypt_ED_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {4d 03 c1 4d 03 c0 49 2b ca 48 03 cd 49 2b d0 46 8a 04 2a 46 32 04 39 49 8d 0c 31 48 0f af c8 } //05 00 
		$a_01_1 = {49 0f af c2 48 2b c1 49 03 c3 48 03 c5 48 ff c5 46 88 04 30 } //00 00 
	condition:
		any of ($a_*)
 
}