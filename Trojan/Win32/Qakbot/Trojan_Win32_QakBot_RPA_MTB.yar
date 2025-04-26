
rule Trojan_Win32_QakBot_RPA_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 01 18 8b 45 c4 03 45 a8 03 45 ac 48 8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}