
rule Trojan_Win32_Cropo_gen_A{
	meta:
		description = "Trojan:Win32/Cropo.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {75 1c 0f b7 45 fe 48 48 0f 84 ab 00 00 00 83 e8 03 0f 84 99 00 00 00 2b c6 74 56 48 74 0c 8b 07 8b cf ff 50 3c } //1
		$a_02_1 = {8b 45 f8 8b 88 ?? ?? 40 00 8b 45 0c 6a ff e8 ?? ?? 00 00 85 c0 59 74 5f 8b 55 08 56 8d bd e4 fb ff ff e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}