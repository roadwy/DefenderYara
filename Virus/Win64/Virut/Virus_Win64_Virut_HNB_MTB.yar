
rule Virus_Win64_Virut_HNB_MTB{
	meta:
		description = "Virus:Win64/Virut.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b c0 0f 50 0f b6 47 fc } //2
		$a_01_1 = {01 04 24 8d 7f f2 } //1
		$a_01_2 = {8d 00 8b cc 1b 51 2c } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}