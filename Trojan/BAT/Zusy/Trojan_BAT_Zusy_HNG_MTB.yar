
rule Trojan_BAT_Zusy_HNG_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 2b 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 2e 00 52 00 65 00 73 00 } //10 ⬀WindowsApp1.Res
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 2e 00 69 00 62 00 62 00 2e 00 63 00 6f 00 2f 00 } //2 https://i.ibb.co/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}