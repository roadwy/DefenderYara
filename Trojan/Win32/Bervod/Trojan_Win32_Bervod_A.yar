
rule Trojan_Win32_Bervod_A{
	meta:
		description = "Trojan:Win32/Bervod.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 02 04 00 00 50 ff 15 ?? ?? ?? ?? 8b 46 64 83 f8 02 7d 4f b9 08 00 00 00 } //1
		$a_00_1 = {00 00 61 00 64 00 4d 00 61 00 6e 00 49 00 65 00 57 00 6e 00 64 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}