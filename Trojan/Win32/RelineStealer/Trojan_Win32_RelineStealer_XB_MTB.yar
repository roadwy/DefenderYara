
rule Trojan_Win32_RelineStealer_XB_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.XB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7c af fc 03 f8 5d 89 bd 90 01 04 33 db b8 90 01 04 83 c0 90 01 01 64 8b 3c 03 8b 7f 0c 8b 77 14 8b 36 8b 36 8b 46 10 8b f8 03 78 90 01 01 8b 57 78 03 d0 8b 7a 20 03 f8 55 8b eb 8b 34 af 03 f0 45 81 3e 90 01 06 81 7e 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}