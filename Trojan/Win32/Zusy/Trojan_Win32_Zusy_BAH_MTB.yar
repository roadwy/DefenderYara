
rule Trojan_Win32_Zusy_BAH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f4 8b 45 f4 89 45 fc 8b 45 fc 8b 40 3c 03 45 f4 89 45 f8 8b 45 f8 8b 40 28 03 45 f4 89 45 f0 8d 45 ec } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}