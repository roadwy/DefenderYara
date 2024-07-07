
rule Trojan_Win64_Bumblebee_IND_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.IND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 43 68 8d 04 4d 90 01 04 89 83 90 01 04 8b 43 90 01 01 48 8b 8b 90 01 04 31 04 11 48 83 c2 04 8b 83 c0 00 00 00 01 43 90 01 01 8b 43 08 2b 83 90 01 04 2d 90 01 04 09 83 90 01 04 48 81 fa 90 01 04 7c 90 00 } //5
		$a_01_1 = {63 73 76 63 72 75 6e } //1 csvcrun
		$a_01_2 = {52 6a 6a 77 39 } //1 Rjjw9
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}