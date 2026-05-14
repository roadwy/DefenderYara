
rule Trojan_Win64_Vidar_LRA_MTB{
	meta:
		description = "Trojan:Win64/Vidar.LRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8a 0c 04 80 f1 db 88 0c 18 48 ff c0 48 83 f8 15 } //20
		$a_01_1 = {8d 48 01 0f af c8 83 e1 01 83 fa 0a } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}