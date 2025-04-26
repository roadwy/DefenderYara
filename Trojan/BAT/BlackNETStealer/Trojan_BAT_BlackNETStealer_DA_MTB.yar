
rule Trojan_BAT_BlackNETStealer_DA_MTB{
	meta:
		description = "Trojan:BAT/BlackNETStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6e 74 68 65 6d 69 61 20 6c 6f 67 67 65 72 } //1 Anthemia logger
		$a_81_1 = {50 61 73 73 77 6f 72 64 53 74 65 61 6c 65 72 } //1 PasswordStealer
		$a_81_2 = {73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //1 screenshot.png
		$a_81_3 = {70 61 73 73 77 6f 72 64 2e 74 78 74 } //1 password.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}