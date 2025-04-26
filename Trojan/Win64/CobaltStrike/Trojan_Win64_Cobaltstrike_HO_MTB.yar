
rule Trojan_Win64_Cobaltstrike_HO_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 41 8d 14 00 48 83 c0 01 31 ca 88 50 ff 4c 39 c8 75 eb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}