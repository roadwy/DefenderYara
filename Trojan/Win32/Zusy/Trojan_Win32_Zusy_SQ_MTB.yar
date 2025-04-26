
rule Trojan_Win32_Zusy_SQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 1f 8b 55 08 03 55 fc 8b 45 0c 03 45 fc 8a 08 88 0a 83 7d fc 00 75 07 c7 45 fc 00 00 00 00 eb d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}