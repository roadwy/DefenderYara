
rule Trojan_Win32_XWorm_NWR_MTB{
	meta:
		description = "Trojan:Win32/XWorm.NWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {e8 49 ff ff ff 3b 43 20 75 ?? 33 c0 89 43 20 eb ?? 8b 43 1c e8 b9 67 fa ff 8b d0 8b c6 e8 ?? ?? ?? ?? 89 43 20 83 c3 } //5
		$a_01_1 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 20 00 2f 00 74 00 20 00 30 00 } //1 shutdown.exe /f /s /t 0
		$a_01_2 = {53 00 74 00 61 00 72 00 74 00 44 00 44 00 6f 00 73 00 } //1 StartDDos
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}