
rule Trojan_BAT_AveMaria_RDE_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 31 } //1 server1
		$a_01_1 = {49 6d 70 6f 72 74 61 6e 74 20 77 69 6e 64 6f 77 73 20 66 69 6c 65 } //1 Important windows file
		$a_01_2 = {53 6f 75 6c 45 20 52 65 76 69 65 77 20 53 77 69 74 63 68 } //1 SoulE Review Switch
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}