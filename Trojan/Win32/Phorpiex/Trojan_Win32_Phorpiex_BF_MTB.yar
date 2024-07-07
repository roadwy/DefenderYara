
rule Trojan_Win32_Phorpiex_BF_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 0f be 4c 05 f4 8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c9 8b 55 08 03 55 fc 0f be 02 f7 d0 8b 4d 08 03 4d fc 88 01 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}