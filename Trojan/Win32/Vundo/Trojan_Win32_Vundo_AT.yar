
rule Trojan_Win32_Vundo_AT{
	meta:
		description = "Trojan:Win32/Vundo.AT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 [0-08] 89 45 fc [0-20] 8b 45 fc [0-08] 8b 40 0c [0-40] 8b 09 [0-04] 39 41 18 [0-04] 0f 85 f1 ff ff ff [0-20] 89 51 1c [0-20] c9 eb } //1
		$a_03_1 = {81 fe 00 7d 00 00 [0-04] 0f 82 ?? 00 00 00 [0-08] 81 fe 00 05 00 00 [0-48] 0f 82 ?? 00 00 00 40 [0-04] 81 fe 80 00 00 00 [0-04] 0f 83 ?? 00 00 00 40 [0-02] 40 } //1
		$a_08_2 = {6e 74 64 6c 6c 2e 64 6c 6c } //1 ntdll.dll
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_08_2  & 1)*1) >=3
 
}