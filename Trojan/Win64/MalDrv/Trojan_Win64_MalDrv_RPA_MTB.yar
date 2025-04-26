
rule Trojan_Win64_MalDrv_RPA_MTB{
	meta:
		description = "Trojan:Win64/MalDrv.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0b 8b 53 0c 39 c1 76 19 01 c2 89 c1 44 8a 14 16 41 31 c2 ff c0 44 89 d2 f7 d2 41 88 54 0d 00 eb de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}