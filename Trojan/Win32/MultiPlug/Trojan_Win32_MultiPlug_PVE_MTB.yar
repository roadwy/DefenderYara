
rule Trojan_Win32_MultiPlug_PVE_MTB{
	meta:
		description = "Trojan:Win32/MultiPlug.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 a4 24 90 01 04 8b 84 24 90 00 } //1
		$a_02_1 = {8b f0 83 c4 04 85 f6 0f 8d 90 09 1f 00 81 ac 24 90 01 04 b3 30 c7 6b 81 84 24 90 01 04 21 f4 7c 36 30 0c 90 01 01 56 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}