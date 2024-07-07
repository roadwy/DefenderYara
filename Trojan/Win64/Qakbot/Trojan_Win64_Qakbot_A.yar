
rule Trojan_Win64_Qakbot_A{
	meta:
		description = "Trojan:Win64/Qakbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 32 44 25 00 ff c5 41 88 00 49 ff c0 49 83 e9 01 } //1
		$a_03_1 = {8b d3 48 89 90 02 04 45 33 c9 48 8d 0d 90 02 08 4c 8b c0 48 8b f8 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}