
rule Trojan_Win64_StrelaStealer_GPAC_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 e1 01 83 f9 00 41 0f 94 c2 83 fa 0a 41 0f 9c c3 44 88 d3 80 f3 ff 80 e3 01 40 b6 01 40 88 f7 40 80 f7 01 45 88 d6 41 20 } //2
		$a_01_1 = {00 6f 75 74 2e 64 6c 6c 00 78 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}