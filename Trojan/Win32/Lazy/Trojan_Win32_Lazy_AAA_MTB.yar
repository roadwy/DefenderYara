
rule Trojan_Win32_Lazy_AAA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f0 0f be 54 0d ?? 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}