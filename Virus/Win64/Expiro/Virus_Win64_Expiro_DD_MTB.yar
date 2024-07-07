
rule Virus_Win64_Expiro_DD_MTB{
	meta:
		description = "Virus:Win64/Expiro.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 55 48 8b ec 48 83 ec 20 48 83 e4 f0 48 8d 90 01 01 d6 90 01 01 f7 ff 90 00 } //1
		$a_03_1 = {04 00 00 48 81 90 01 02 04 00 00 48 81 90 01 02 c0 08 00 90 09 04 00 48 81 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}