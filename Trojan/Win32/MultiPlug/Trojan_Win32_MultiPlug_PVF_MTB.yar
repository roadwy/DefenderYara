
rule Trojan_Win32_MultiPlug_PVF_MTB{
	meta:
		description = "Trojan:Win32/MultiPlug.PVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 a4 24 90 01 04 8b 84 24 90 01 04 81 84 24 90 01 04 f3 ae ac 68 81 ac 24 90 01 04 b3 30 c7 6b 81 84 24 90 01 04 21 f4 7c 36 30 0c 1e 56 e8 90 01 04 8b f0 83 c4 04 85 f6 0f 89 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}