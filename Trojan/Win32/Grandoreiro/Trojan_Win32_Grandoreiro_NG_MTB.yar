
rule Trojan_Win32_Grandoreiro_NG_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {e8 e3 f1 ff ff eb 10 8b cb 0f af 4d 90 01 01 8b d6 8b 45 90 01 01 e8 39 8f ff ff 8b 45 90 01 01 8b 55 f8 e8 0e 00 00 00 8b 45 08 90 00 } //01 00 
		$a_01_1 = {42 69 6c 73 79 6e 63 2e 65 78 65 } //00 00  Bilsync.exe
	condition:
		any of ($a_*)
 
}