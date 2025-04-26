
rule Trojan_Win32_AveMaria_NEDR_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}