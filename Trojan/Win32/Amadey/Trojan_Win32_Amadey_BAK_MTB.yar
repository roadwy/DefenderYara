
rule Trojan_Win32_Amadey_BAK_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d f8 8d 4d d8 0f 43 cf 03 c2 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 04 85 90 02 04 32 04 31 8b 4d f8 88 86 90 02 04 46 3b 75 f4 7c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}