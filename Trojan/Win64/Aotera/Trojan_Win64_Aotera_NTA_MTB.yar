
rule Trojan_Win64_Aotera_NTA_MTB{
	meta:
		description = "Trojan:Win64/Aotera.NTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 33 f9 48 c1 c7 1f 8b 55 a8 ff c2 83 fa 08 } //2
		$a_01_1 = {2b c1 44 6b 45 a8 0d 41 03 c0 25 ff 0f 00 00 41 3b 47 08 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}