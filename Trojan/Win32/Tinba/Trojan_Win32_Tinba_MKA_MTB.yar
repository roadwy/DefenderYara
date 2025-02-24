
rule Trojan_Win32_Tinba_MKA_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4a 0c 8b 95 ?? ?? ff ff 8a 0c 11 8b 95 ?? ?? ff ff 32 0c 10 8b 95 a8 fe ff ff 88 0c 10 ff d7 8b d0 8d 8d ?? ?? ff ff ff d6 50 6a 6b ff d7 8b d0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}