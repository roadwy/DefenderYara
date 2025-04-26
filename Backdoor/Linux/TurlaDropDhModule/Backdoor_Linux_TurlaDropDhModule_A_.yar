
rule Backdoor_Linux_TurlaDropDhModule_A_{
	meta:
		description = "Backdoor:Linux/TurlaDropDhModule.A!!TurlaDropDhModule.A,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {da e1 01 cd d8 c9 70 af c2 e4 f2 7a 41 8b 43 39 52 9b 4b 4d e5 85 f8 49 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}