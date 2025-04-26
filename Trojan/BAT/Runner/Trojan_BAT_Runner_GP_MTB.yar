
rule Trojan_BAT_Runner_GP_MTB{
	meta:
		description = "Trojan:BAT/Runner.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 69 20 ad 00 00 00 61 9d 11 0e } //2
		$a_01_1 = {47 69 1f 44 61 9d 11 0e } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}