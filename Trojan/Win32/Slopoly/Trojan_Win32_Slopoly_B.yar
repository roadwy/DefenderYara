
rule Trojan_Win32_Slopoly_B{
	meta:
		description = "Trojan:Win32/Slopoly.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {62 6f 74 5f 69 70 3a } //bot_ip:  1
		$a_80_1 = {65 6c 65 76 61 74 65 64 3a } //elevated:  1
		$a_80_2 = {73 65 73 73 69 6f 6e 5f 69 64 3a } //session_id:  1
		$a_80_3 = {75 73 65 72 3a } //user:  1
		$a_80_4 = {62 6f 74 3a } //bot:  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}