
rule Trojan_BAT_Taskun_NC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 26 61 19 11 20 58 61 11 34 61 d2 9c 17 11 0b } //5
		$a_03_1 = {d4 91 07 06 69 1f 16 5d 90 01 02 00 00 0a 61 11 0c 59 90 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}