
rule Trojan_Win64_Vidar_GZ_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c1 0f b6 c9 0f b6 ac 0c e0 01 00 00 40 00 ea 0f b6 f2 44 0f b6 b4 34 e0 01 00 00 44 88 b4 0c e0 01 00 00 40 88 ac 34 e0 01 00 00 40 02 ac 0c e0 01 00 00 44 0f b6 f5 42 0f b6 ac 34 e0 01 00 00 43 30 2c 1a 49 ff c3 49 83 fb 40 75 b2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}