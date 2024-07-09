
rule Trojan_Win32_Lokibot_SY_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec ff 75 0c 90 05 10 01 90 8a 45 08 90 05 10 01 90 5f 90 05 10 01 90 30 07 5d c2 08 00 } //1
		$a_01_1 = {bb 01 00 00 00 8b ca 03 cb c6 01 14 43 48 75 f5 33 c0 5b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}