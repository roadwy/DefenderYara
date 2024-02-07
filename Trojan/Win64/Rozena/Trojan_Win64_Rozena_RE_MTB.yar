
rule Trojan_Win64_Rozena_RE_MTB{
	meta:
		description = "Trojan:Win64/Rozena.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 63 c1 48 8d 54 24 90 01 01 48 03 d0 8d 41 90 01 01 30 02 ff c1 83 f9 03 72 e9 90 00 } //01 00 
		$a_01_1 = {64 69 73 63 6f 72 64 } //00 00  discord
	condition:
		any of ($a_*)
 
}