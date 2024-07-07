
rule Trojan_Win32_Lockbit_MBFV_MTB{
	meta:
		description = "Trojan:Win32/Lockbit.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 dc 89 45 f8 8b 45 e4 31 45 fc 8b 45 fc 33 45 f8 81 45 f0 90 01 04 2b f0 ff 4d e0 89 45 fc 90 00 } //1
		$a_03_1 = {72 b5 33 db a1 90 01 04 03 c3 3d 8d 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}