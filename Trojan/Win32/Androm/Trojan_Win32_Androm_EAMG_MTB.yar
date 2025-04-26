
rule Trojan_Win32_Androm_EAMG_MTB{
	meta:
		description = "Trojan:Win32/Androm.EAMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 14 41 0f be 45 97 03 d0 8b 8d f0 fe ff ff 03 4d a0 88 11 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}