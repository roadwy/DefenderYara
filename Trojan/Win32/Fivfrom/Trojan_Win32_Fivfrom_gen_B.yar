
rule Trojan_Win32_Fivfrom_gen_B{
	meta:
		description = "Trojan:Win32/Fivfrom.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c1 ac 32 05 ?? ?? ?? ?? aa e2 f6 } //1
		$a_03_1 = {b9 ff ff 2f 00 31 c0 83 c0 ?? 50 51 6a 00 e8 ?? ?? ?? ?? 59 58 e2 f0 } //1
		$a_01_2 = {b9 ff ff ff ff 8b 45 08 8b 00 83 f8 00 74 07 b9 05 00 00 00 e2 ef fa fa fa fa 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}