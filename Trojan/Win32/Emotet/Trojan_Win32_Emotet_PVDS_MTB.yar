
rule Trojan_Win32_Emotet_PVDS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVDS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 51 8b 4d 0c 03 4d fc 88 01 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}