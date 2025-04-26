
rule Trojan_Win32_Genbot_RPX_MTB{
	meta:
		description = "Trojan:Win32/Genbot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 0c 8b f4 8d 45 f4 50 6a 00 6a 00 8b 4d dc 51 6a 00 6a 00 ff 15 } //1
		$a_01_1 = {8b f4 6a 40 68 00 10 00 00 8b 45 0c 50 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}