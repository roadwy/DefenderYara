
rule Trojan_Win32_Sefnit_AK{
	meta:
		description = "Trojan:Win32/Sefnit.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 75 18 8b 45 f4 ff 75 14 03 c6 ff 75 10 ff 75 0c a3 ?? ?? ?? ?? ff 75 08 ff 15 } //1
		$a_03_1 = {6b f6 28 8d 74 32 04 [0-10] 83 3e 00 74 [0-10] 83 c6 04 83 [0-02] 0a 7c ?? eb [0-08] 6b ?? 0a [0-10] 89 ?? ?? 04 } //1
		$a_03_2 = {0f be c3 69 c0 [0-08] 05 ?? ?? ?? ?? (e9|eb) } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}