
rule Trojan_Win64_Turtleloader_AA_MTB{
	meta:
		description = "Trojan:Win64/Turtleloader.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c8 48 99 49 f7 fb 41 8a 04 12 41 32 04 09 88 04 0e 48 ff c1 48 81 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}