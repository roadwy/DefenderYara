
rule Trojan_Win32_Redline_CCAR_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 55 c7 c1 e2 90 01 01 0b ca 88 4d c7 0f b6 45 c7 33 45 c8 88 45 c7 0f b6 4d c7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}