
rule Trojan_Win32_Sytro_RPY_MTB{
	meta:
		description = "Trojan:Win32/Sytro.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 50 58 30 00 64 e5 fb } //1
		$a_01_1 = {55 50 58 31 00 55 00 } //1
		$a_01_2 = {2e 74 73 75 73 74 75 00 } //1 琮畳瑳u
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}