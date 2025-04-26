
rule Trojan_Win64_Cobaltstrike_AE_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 01 30 01 48 8d 49 01 41 0f b6 01 44 6b c0 ?? 41 80 c0 ?? 45 88 01 48 83 ea ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}