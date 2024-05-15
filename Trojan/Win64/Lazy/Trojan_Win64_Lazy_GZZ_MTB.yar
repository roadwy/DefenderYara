
rule Trojan_Win64_Lazy_GZZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 5f 41 5e 41 5d 41 5c 5f 5e 5d c3 30 40 02 00 91 40 02 00 91 40 02 00 45 40 02 00 45 40 02 00 } //00 00 
	condition:
		any of ($a_*)
 
}