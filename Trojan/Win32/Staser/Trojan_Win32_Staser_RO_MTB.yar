
rule Trojan_Win32_Staser_RO_MTB{
	meta:
		description = "Trojan:Win32/Staser.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 [0-10] 8b 75 14 56 ff 15 ?? ?? 46 00 56 ff 15 ?? ?? 46 00 3d ?? ?? ?? ?? 5e 75 05 e8 ?? 29 ff ff e9 } //5
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ShutdownScheduler.exe
		$a_01_2 = {41 00 63 00 65 00 62 00 79 00 74 00 65 00 } //1 Acebyte
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}