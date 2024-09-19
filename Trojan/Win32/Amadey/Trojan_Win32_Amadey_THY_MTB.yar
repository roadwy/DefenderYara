
rule Trojan_Win32_Amadey_THY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.THY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 46 89 45 fc 83 6d fc 28 83 6d fc ?? 8b 45 08 8a 4d fc 03 c6 30 08 46 3b 75 0c 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}