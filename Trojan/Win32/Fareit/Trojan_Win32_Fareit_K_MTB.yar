
rule Trojan_Win32_Fareit_K_MTB{
	meta:
		description = "Trojan:Win32/Fareit.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 08 90 05 04 01 90 8a 10 80 f2 ?? 90 05 04 01 90 88 10 5d c2 04 00 } //1
		$a_03_1 = {8b 06 03 c3 50 ff 15 ?? ?? ?? ?? 90 05 04 01 90 ff 06 81 3e ?? ?? ?? ?? 75 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}