
rule Trojan_Win32_Alureon_FH{
	meta:
		description = "Trojan:Win32/Alureon.FH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 62 63 6b 66 67 2e 74 6d 70 00 } //1
		$a_03_1 = {b8 4c 01 00 00 66 39 46 04 0f 85 ?? ?? ?? ?? 83 c0 bf 66 39 46 18 0f 85 ?? ?? ?? ?? 0f b7 46 14 8d 7c 30 18 8b 46 50 6a 40 68 00 30 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}