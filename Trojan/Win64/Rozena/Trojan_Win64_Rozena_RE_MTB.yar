
rule Trojan_Win64_Rozena_RE_MTB{
	meta:
		description = "Trojan:Win64/Rozena.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c1 48 8d 54 24 ?? 48 03 d0 8d 41 ?? 30 02 ff c1 83 f9 03 72 e9 } //5
		$a_01_1 = {64 69 73 63 6f 72 64 } //1 discord
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}