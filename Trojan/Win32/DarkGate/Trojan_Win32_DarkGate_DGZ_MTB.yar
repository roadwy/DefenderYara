
rule Trojan_Win32_DarkGate_DGZ_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.DGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e6 8b c6 8b cd 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 1b 2b c8 03 ce 8a 44 0c 20 32 86 ?? ?? ?? ?? 46 88 47 ff 81 fe 00 d4 16 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}