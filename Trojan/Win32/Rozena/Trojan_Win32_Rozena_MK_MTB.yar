
rule Trojan_Win32_Rozena_MK_MTB{
	meta:
		description = "Trojan:Win32/Rozena.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 46 18 8b 86 90 01 04 2b 86 90 01 04 2d 3a 67 02 00 01 86 90 01 04 8b 4e 5c 8b 86 90 01 04 88 1c 01 ff 46 5c 8b 86 90 01 04 35 90 01 04 29 86 90 01 04 8b 86 90 01 04 83 f0 13 0f af 46 1c 89 46 1c 8b 86 90 01 04 09 86 90 01 04 81 ff 90 01 04 0f 8c 90 00 } //01 00 
		$a_03_1 = {31 0c 32 83 c6 90 01 01 8b 48 90 01 01 83 f1 90 01 01 29 88 90 01 04 8b 88 90 01 04 83 f1 01 0f af 48 90 01 01 89 48 64 8b 88 90 01 04 01 48 6c 81 fe 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}