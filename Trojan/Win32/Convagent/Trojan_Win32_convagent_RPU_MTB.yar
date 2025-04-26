
rule Trojan_Win32_convagent_RPU_MTB{
	meta:
		description = "Trojan:Win32/convagent.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 34 24 5b 50 89 14 24 89 2c 24 89 e5 81 c5 04 00 00 00 83 c5 04 87 2c 24 5c } //1
		$a_01_1 = {8b 14 24 50 89 2c 24 89 1c 24 54 5b 81 c3 04 00 00 00 83 c3 04 87 1c 24 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}