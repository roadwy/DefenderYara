
rule Trojan_Win32_Tepfer_RB_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 a1 2c 00 00 00 c7 45 dc 7b 7d 6b 7c c7 45 e0 7e 7c 61 68 c7 45 e4 67 62 6b 2e 8b 38 } //1
		$a_01_1 = {c7 45 e0 6d 6d 42 4b c7 45 e4 4f 40 4b 5c c6 45 bf 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}