
rule Trojan_Win32_Bayrob_NIT_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 49 ab ff ff 66 89 15 ?? ?? ?? 00 8a 17 30 11 dd 05 ?? ?? ?? 00 d8 c1 41 47 dc 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 3b c8 75 d6 } //3
		$a_01_1 = {8b 72 08 8b 1c 37 89 1c 8e 8b 72 04 bb 01 00 00 00 03 cb 2b f0 83 c7 04 3b ce 7c e4 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}