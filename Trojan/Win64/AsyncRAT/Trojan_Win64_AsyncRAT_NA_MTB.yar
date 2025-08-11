
rule Trojan_Win64_AsyncRAT_NA_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 54 24 68 48 89 94 24 b0 00 00 00 48 c7 84 24 c8 00 00 00 08 00 00 00 48 8d 15 a1 66 02 00 48 89 94 24 c0 00 00 00 } //2
		$a_01_1 = {4c 8d 0d e4 5e 02 00 4c 89 8c 24 f0 00 00 00 48 89 94 24 08 01 00 00 4c 89 84 24 00 01 00 00 48 8d 05 e5 63 02 00 bb 07 00 00 00 48 8d 8c 24 f0 00 00 00 bf 02 00 00 00 48 89 fe e8 b6 b3 ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}