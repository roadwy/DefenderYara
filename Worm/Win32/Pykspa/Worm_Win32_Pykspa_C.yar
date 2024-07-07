
rule Worm_Win32_Pykspa_C{
	meta:
		description = "Worm:Win32/Pykspa.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 33 f6 83 c4 90 01 01 39 75 0c 76 2e 8d 45 f0 50 8d 45 f4 50 8d 85 f0 fc ff ff 50 8d 45 fc 50 8d 45 f8 50 33 c0 8a 04 3e 50 e8 90 01 02 ff ff 83 c4 18 88 04 3e 46 3b 75 0c 72 d2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}