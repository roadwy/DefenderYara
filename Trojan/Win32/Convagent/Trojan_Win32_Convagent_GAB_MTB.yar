
rule Trojan_Win32_Convagent_GAB_MTB{
	meta:
		description = "Trojan:Win32/Convagent.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 30 0f af 00 00 01 cd 8b 48 2c } //10
		$a_01_1 = {00 cd 8b 48 54 0f af 4e 00 00 cd 8b 48 50 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}