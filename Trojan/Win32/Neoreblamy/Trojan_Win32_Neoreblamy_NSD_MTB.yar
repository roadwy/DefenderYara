
rule Trojan_Win32_Neoreblamy_NSD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 65 d8 00 eb 07 8b 45 d8 40 89 45 d8 81 7d d8 } //1
		$a_01_1 = {8b 45 fc 33 45 f8 99 89 45 f0 89 55 f4 8d 45 f0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}