
rule Trojan_BAT_Convagent_ARA_MTB{
	meta:
		description = "Trojan:BAT/Convagent.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 6e 65 77 79 6f 72 6b 74 6c 69 6d 65 73 2e 6c 69 66 65 2f 61 70 69 2f 76 61 6c 75 65 73 2f 69 64 } //://newyorktlimes.life/api/values/id  2
		$a_01_1 = {5c 77 6f 72 6b 2e 75 61 2e 70 64 62 } //2 \work.ua.pdb
		$a_01_2 = {24 63 39 36 62 65 30 61 34 2d 63 33 39 31 2d 34 32 31 65 2d 39 31 37 65 2d 33 66 65 34 38 34 64 34 63 32 65 34 } //2 $c96be0a4-c391-421e-917e-3fe484d4c2e4
	condition:
		((#a_80_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}