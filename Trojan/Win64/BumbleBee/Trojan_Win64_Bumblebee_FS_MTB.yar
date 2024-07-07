
rule Trojan_Win64_Bumblebee_FS_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.FS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 8a 0c 17 2a 8c 24 88 00 00 00 32 8c 24 80 00 00 00 49 8b 43 20 41 88 0c 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}