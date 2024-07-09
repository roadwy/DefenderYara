
rule Trojan_Win32_Grandoreiro_psyI_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {79 6e 6a 78 68 7c 00 00 ff ff ff ff 0f 00 00 00 57 69 6e 53 65 76 65 6e 55 70 64 61 74 65 72 00 55 8b ec b9 7a 00 00 00 6a 00 6a 00 49 75 f9 51 89 45 fc 8b 45 fc e8 2d ce fe ff 8d 85 a4 fe ff ff 8b 15 5c a1 40 00 [0-05] fe ff 33 c0 55 68 36 7f 41 00 64 ff 30 64 89 20 68 00 01 00 00 8d 85 a4 fd ff ff 50 6a 00 e8 47 e9 fe ff 8d 95 50 fc ff ff b8 4c 7f 41 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}