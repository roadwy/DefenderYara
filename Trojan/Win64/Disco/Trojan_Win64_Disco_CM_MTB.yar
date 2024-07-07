
rule Trojan_Win64_Disco_CM_MTB{
	meta:
		description = "Trojan:Win64/Disco.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 4c 05 39 48 03 c7 48 83 f8 07 73 05 8a 4d 38 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}