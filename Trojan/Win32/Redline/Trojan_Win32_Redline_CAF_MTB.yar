
rule Trojan_Win32_Redline_CAF_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 8d 54 fd ff ff 2b c1 8b 4d a4 2b 8d 24 fe ff ff 8b 95 34 ff ff ff 2b d1 2b c2 a3 [0-04] 81 bd 60 ff ff ff b5 11 00 00 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}