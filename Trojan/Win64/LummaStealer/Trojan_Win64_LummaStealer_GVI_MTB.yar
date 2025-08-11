
rule Trojan_Win64_LummaStealer_GVI_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af e8 40 f6 c5 01 0f 94 44 24 2c 83 fa 0a 0f 9c 44 24 2d 4d 89 ce 4d 89 c5 48 89 ce } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}