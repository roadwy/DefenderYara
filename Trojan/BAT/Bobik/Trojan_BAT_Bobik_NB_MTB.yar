
rule Trojan_BAT_Bobik_NB_MTB{
	meta:
		description = "Trojan:BAT/Bobik.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 04 17 94 59 11 04 16 94 59 9e } //2
		$a_01_1 = {11 04 18 94 59 11 04 17 94 59 11 04 16 94 } //2
		$a_01_2 = {43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 Client.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}