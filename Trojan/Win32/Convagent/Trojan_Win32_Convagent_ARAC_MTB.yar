
rule Trojan_Win32_Convagent_ARAC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 14 8b 55 08 03 55 fc 8a 02 34 c5 8b 4d 08 03 4d fc 88 01 eb db } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}