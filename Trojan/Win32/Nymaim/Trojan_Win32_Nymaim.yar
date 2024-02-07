
rule Trojan_Win32_Nymaim{
	meta:
		description = "Trojan:Win32/Nymaim,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 fe 00 74 90 01 01 31 c0 2b 01 f7 d8 f8 83 d9 fc f8 83 d8 1e 01 d0 f8 83 d0 ff 8d 10 50 8f 07 8d 7f 04 8d 76 fc eb 90 00 } //01 00 
		$a_01_1 = {6f 64 62 63 63 6f 6e 66 2e 64 6c 6c 00 63 6e 61 61 61 72 6f 5f 65 73 73 5f 5f 6d 6f 72 79 00 63 69 72 74 75 75 6c 41 6c 6c 6f 63 00 64 62 72 6e 65 6c 33 32 2e 64 6c 6c } //00 00  摯换潣普搮汬挀慮慡潲敟獳彟潭祲挀物畴汵汁潬c扤湲汥㈳搮汬
	condition:
		any of ($a_*)
 
}