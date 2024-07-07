
rule Trojan_Win64_Bumblebee_SS_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 7f 48 33 c1 89 45 7f 48 63 45 6f 49 8b 95 e8 00 00 00 48 63 4d f7 48 0f af d0 49 63 c1 48 33 ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}