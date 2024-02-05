
rule Trojan_Win32_SmokeLoader_FRX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7d 1b 75 77 6b c6 25 b5 ad 1b 73 22 f4 82 29 a1 5c f2 2b 20 3b 58 48 75 b9 f4 d4 12 b2 6b db 44 52 e6 61 c0 43 fe 6a 7f ae 2f ef 7b 7d 43 16 cb } //00 00 
	condition:
		any of ($a_*)
 
}