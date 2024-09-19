
rule Trojan_Win64_Zusy_RE_MTB{
	meta:
		description = "Trojan:Win64/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 84 24 b0 02 00 00 33 c9 ff 15 dd 14 00 00 48 8b c8 ff 15 e4 14 00 00 48 8d 05 f5 15 00 00 48 89 44 24 48 48 c7 44 24 60 ?? ?? 00 00 c6 44 24 40 00 48 c7 44 24 58 00 04 00 00 b9 02 02 00 00 48 8d 94 24 10 01 00 00 ff 15 6e 13 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}