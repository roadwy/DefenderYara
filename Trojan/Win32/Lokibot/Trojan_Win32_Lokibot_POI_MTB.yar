
rule Trojan_Win32_Lokibot_POI_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.POI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 0c 30 8a 09 90 80 f1 dc 8d 1c 30 88 0b 40 4a 75 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}