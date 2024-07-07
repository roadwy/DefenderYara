
rule Virus_Win64_Sirefef_B{
	meta:
		description = "Virus:Win64/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 bc fd ff ff 3b c7 7c 1b 48 8b 84 24 e0 00 00 00 66 39 78 06 74 0d 48 83 c0 0c 45 33 c0 33 d2 33 c9 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Virus_Win64_Sirefef_B_2{
	meta:
		description = "Virus:Win64/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 bc fd ff ff 3b c7 7c 1b 48 8b 84 24 e0 00 00 00 66 39 78 06 74 0d 48 83 c0 0c 45 33 c0 33 d2 33 c9 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}