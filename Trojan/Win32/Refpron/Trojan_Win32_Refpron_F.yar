
rule Trojan_Win32_Refpron_F{
	meta:
		description = "Trojan:Win32/Refpron.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {0d ba db 00 8b 45 f0 50 a1 ?? ?? ?? ?? 8b 00 ff d0 89 45 ec 81 7d ec 02 01 00 00 90 13 c6 45 fb 01 33 c0 } //1
		$a_03_1 = {c7 45 e4 6d ce 00 00 [0-20] 66 05 bf 58 } //1
		$a_03_2 = {b8 32 00 00 00 e8 ?? ?? ?? ?? 83 c0 0a 89 45 ?? 69 45 ?? e8 03 00 00 e8 } //1
		$a_01_3 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 72 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}