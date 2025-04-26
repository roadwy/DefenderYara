
rule TrojanSpy_Win64_Stealer_PAGM_MTB{
	meta:
		description = "TrojanSpy:Win64/Stealer.PAGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 4d 8b c2 80 e1 07 c0 e1 03 49 d3 e8 46 30 04 08 48 ff c0 48 83 f8 } //2
		$a_01_1 = {8d 0c 1f 80 e1 07 c0 e1 03 49 8b d1 48 d3 ea 30 57 ff 40 0f b6 cf 41 2a c8 80 e1 07 c0 e1 03 49 8b d1 48 d3 ea 30 17 48 83 c7 02 48 8d 04 3b 48 83 f8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}