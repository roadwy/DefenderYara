
rule PWS_Win32_Zuten_OB_MTB{
	meta:
		description = "PWS:Win32/Zuten.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 1f 33 d2 8a 14 37 03 c2 8b 55 90 01 01 83 c2 90 01 01 8b ca 33 d2 f7 f1 8a 04 17 88 45 90 01 01 8d 45 90 01 01 8b 55 90 01 01 8b 4d 90 01 01 8a 54 90 01 02 8a 4d 90 01 01 32 d1 e8 90 01 04 8b 55 90 01 01 8d 45 90 01 01 e8 90 01 04 ff 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}