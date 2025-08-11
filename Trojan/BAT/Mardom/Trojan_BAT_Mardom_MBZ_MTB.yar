
rule Trojan_BAT_Mardom_MBZ_MTB{
	meta:
		description = "Trojan:BAT/Mardom.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 62 61 77 6f 6d 69 73 2e 4e 75 79 61 64 65 76 2e 49 79 65 6c 61 } //2 Abawomis.Nuyadev.Iyela
		$a_01_1 = {52 72 48 68 37 } //1 RrHh7
		$a_01_2 = {52 6f 6b 69 6a 61 6c } //1 Rokijal
		$a_01_3 = {6e 74 71 6a 72 7a 7a 6e 70 79 6b 6a 6d } //1 ntqjrzznpykjm
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}