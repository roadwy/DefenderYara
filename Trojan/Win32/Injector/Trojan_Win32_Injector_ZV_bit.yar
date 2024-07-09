
rule Trojan_Win32_Injector_ZV_bit{
	meta:
		description = "Trojan:Win32/Injector.ZV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 8d 05 c4 70 46 00 ff 10 90 09 0b 00 68 ?? ?? ?? ?? 8b 3c ?? c6 07 4c } //1
		$a_03_1 = {23 19 83 e9 ?? f7 d3 8d 5b ?? c1 cb 09 d1 c3 01 fb 8d 5b ff 53 5f c1 c7 09 d1 cf 89 1e f8 83 d6 04 f8 83 d0 04 eb cf } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}