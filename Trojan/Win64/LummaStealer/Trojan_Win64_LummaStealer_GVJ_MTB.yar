
rule Trojan_Win64_LummaStealer_GVJ_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 70 ff 0f af f0 40 f6 c6 01 0f 94 44 24 22 83 fa 0a 0f 9c 44 24 23 48 89 ce ba } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}