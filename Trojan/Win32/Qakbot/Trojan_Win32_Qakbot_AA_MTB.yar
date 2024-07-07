
rule Trojan_Win32_Qakbot_AA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 c0 8a fc 8a e6 d3 cb ff 4d 90 01 01 75 90 01 01 89 4d 90 01 01 2b 4d 90 01 01 09 d9 83 e0 00 09 c8 8b 4d 90 01 01 59 aa 49 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Qakbot_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 1c 30 8b 55 90 01 01 d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d 90 00 } //1
		$a_03_1 = {d3 c0 8a fc 8a e6 d3 cb ff 4d 90 01 01 75 90 01 01 59 8b c3 aa 49 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}