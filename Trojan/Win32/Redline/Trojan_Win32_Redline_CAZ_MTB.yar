
rule Trojan_Win32_Redline_CAZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 8b ce c1 e9 05 8d 1c 37 c7 05 90 02 04 19 36 6b ff c7 05 90 02 04 ff ff ff ff 89 4c 24 14 8b 44 24 24 01 44 24 14 81 3d 90 02 04 79 09 00 00 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}