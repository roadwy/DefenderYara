
rule Trojan_Win32_Guloader_SMTK_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SMTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 8a 88 00 c0 [0-02] 00 88 4d ff 8b 55 d8 03 55 f0 8a 02 88 45 fe 0f b6 4d ff c1 f9 03 0f b6 55 ff c1 e2 05 0b ca 0f b6 45 fe 33 c8 8b 55 f8 88 8a 00 c0 [0-02] 00 8b 45 f0 83 c0 01 99 b9 0d 00 00 00 f7 f9 89 55 f0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}