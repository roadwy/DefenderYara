
rule Trojan_Win32_GandCrypt_DSC_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.DSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 6a 00 05 c3 9e 26 00 6a 00 a3 90 01 04 ff 15 90 01 04 a0 90 01 04 30 04 3e 46 3b f3 7c 90 09 05 00 a1 90 00 } //01 00 
		$a_81_1 = {44 65 20 62 65 6d 6f 6a 65 79 75 7a 65 20 62 61 7a 6f 62 75 70 75 79 6f 62 75 6d 65 74 65 6c 61 77 65 66 69 62 75 20 64 69 77 75 7a 61 20 68 69 62 65 6c 69 67 61 63 61 6b 75 6a 61 6b 61 63 6f } //00 00  De bemojeyuze bazobupuyobumetelawefibu diwuza hibeligacakujakaco
	condition:
		any of ($a_*)
 
}