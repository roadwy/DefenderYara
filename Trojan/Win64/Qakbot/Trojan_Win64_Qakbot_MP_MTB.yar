
rule Trojan_Win64_Qakbot_MP_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 9c c7 45 a4 00 10 00 00 6a 40 8b 45 a4 50 8b 45 a0 03 45 c0 50 6a 00 ff 55 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}