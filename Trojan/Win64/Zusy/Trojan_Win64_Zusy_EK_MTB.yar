
rule Trojan_Win64_Zusy_EK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 00 61 00 6d 00 65 00 20 00 52 00 65 00 70 00 61 00 63 00 6b 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //1 Game Repack Install
		$a_01_1 = {2e 74 68 65 6d 69 64 61 00 c0 76 00 00 60 15 00 00 00 00 00 00 b2 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}