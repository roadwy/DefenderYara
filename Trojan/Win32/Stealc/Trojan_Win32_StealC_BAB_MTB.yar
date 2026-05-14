
rule Trojan_Win32_StealC_BAB_MTB{
	meta:
		description = "Trojan:Win32/StealC.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 08 64 8b 0d 30 00 00 00 89 4d a0 8b 55 a0 8b 45 f0 89 42 08 8b 4d f4 8b 55 f0 03 51 10 89 55 9c 8b f4 ff 55 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}