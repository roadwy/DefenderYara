
rule Trojan_BAT_Diztakun_ND_MTB{
	meta:
		description = "Trojan:BAT/Diztakun.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {7e 4b 00 00 0a 08 6f 5a 00 00 0a 0a 06 72 15 08 00 70 07 6f 5b 00 00 0a } //3
		$a_01_1 = {24 31 33 61 65 61 63 37 33 2d 65 61 30 33 2d 34 31 35 66 2d 62 32 37 37 2d 38 36 39 30 65 65 65 66 33 61 37 62 } //1 $13aeac73-ea03-415f-b277-8690eeef3a7b
		$a_01_2 = {4f 6e 6c 69 6e 65 45 78 61 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 OnlineExam.Properties.Resources
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}