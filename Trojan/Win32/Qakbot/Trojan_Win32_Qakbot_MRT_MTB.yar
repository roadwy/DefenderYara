
rule Trojan_Win32_Qakbot_MRT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2c d3 2c dc 2c f6 2c 52 2c 40 2c e0 20 26 2c b1 2c e0 45 37 2c 3e 2c e0 2c 88 2c 41 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}