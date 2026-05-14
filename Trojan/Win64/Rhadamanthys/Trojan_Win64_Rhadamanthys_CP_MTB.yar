
rule Trojan_Win64_Rhadamanthys_CP_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8d 05 ?? ?? ?? ?? 0f b6 0c 02 48 8b 55 ?? 48 8b 45 ?? 48 01 d0 44 89 c2 31 ca 88 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}