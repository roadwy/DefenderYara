
rule Trojan_Win64_Bumblebee_TR_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.TR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 8b 84 00 00 00 88 14 01 ff 83 84 00 00 00 8b 83 04 01 00 00 03 43 0c 33 43 64 48 63 8b 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}