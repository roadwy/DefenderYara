
rule Trojan_Win64_Phave_GVB_MTB{
	meta:
		description = "Trojan:Win64/Phave.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 e5 89 d0 89 ca 88 55 10 88 45 18 0f b6 45 10 32 45 18 } //2
		$a_01_1 = {88 03 48 83 85 18 12 00 00 01 48 8b 85 18 12 00 00 48 3b 85 10 12 00 00 72 af } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}