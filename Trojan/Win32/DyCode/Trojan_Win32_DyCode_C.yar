
rule Trojan_Win32_DyCode_C{
	meta:
		description = "Trojan:Win32/DyCode.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 10 64 ff 35 30 00 00 00 81 6d c8 6b 1e 01 00 8b 3d ?? ?? ?? 00 ff d7 } //1
		$a_01_1 = {66 bf 80 00 be ef 00 00 00 bf fb 00 00 00 b9 a5 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}