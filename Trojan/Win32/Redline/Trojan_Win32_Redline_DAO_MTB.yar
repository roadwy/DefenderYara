
rule Trojan_Win32_Redline_DAO_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 0f b6 f1 ba [0-04] e8 [0-04] 50 e8 [0-04] 83 c4 04 0f b6 84 35 e8 fe ff ff 32 87 [0-04] 88 87 [0-04] 47 89 bd d4 fe ff ff 8b b5 d8 fe ff ff e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}