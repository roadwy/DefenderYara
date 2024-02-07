
rule Trojan_Win32_StealerGen_HNU_MTB{
	meta:
		description = "Trojan:Win32/StealerGen.HNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {88 f1 30 c1 20 f1 88 d8 34 90 01 01 88 ce 80 f6 90 01 01 88 d7 80 f7 90 01 01 88 c5 90 00 } //01 00 
		$a_01_1 = {30 40 2e 65 68 5f 66 72 61 6d } //01 00  0@.eh_fram
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}