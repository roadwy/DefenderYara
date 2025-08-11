
rule Trojan_Win32_Tepfer_EAHR_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.EAHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 03 8b 8d 00 ef ff ff 8a 5c 08 03 88 9d 04 ef ff ff c0 e3 02 81 3d ?? ?? ?? ?? 09 0d 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}