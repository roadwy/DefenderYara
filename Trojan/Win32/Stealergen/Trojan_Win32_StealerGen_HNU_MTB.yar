
rule Trojan_Win32_StealerGen_HNU_MTB{
	meta:
		description = "Trojan:Win32/StealerGen.HNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {88 f1 30 c1 20 f1 88 d8 34 ?? 88 ce 80 f6 ?? 88 d7 80 f7 ?? 88 c5 } //10
		$a_01_1 = {30 40 2e 65 68 5f 66 72 61 6d } //1 0@.eh_fram
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}