
rule Trojan_BAT_AgentTesla_SP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 06 17 1f 64 6f 90 01 03 0a 0b 02 7b 2f 00 00 04 6f 90 01 03 0a 07 8c 32 00 00 01 6f 90 01 03 0a 26 00 08 17 58 0c 08 1f 0a fe 02 16 fe 01 0d 09 2d cd 90 00 } //2
		$a_01_1 = {42 61 69 54 61 70 54 68 69 65 74 4b 65 46 6f 72 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 BaiTapThietKeForm.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}