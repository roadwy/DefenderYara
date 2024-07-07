
rule Trojan_Win32_Emotet_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 f7 f1 8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}