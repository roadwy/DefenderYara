
rule Trojan_Win64_IcedID_AMMF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c6 48 f7 e1 48 c1 ea 90 02 0a 48 2b c8 0f b6 44 0d 90 01 01 41 30 41 fe 49 ff cb 90 00 } //1
		$a_03_1 = {48 f7 e1 48 c1 ea 90 02 0a 48 2b c8 49 03 cb 0f b6 44 0c 90 01 01 42 32 44 13 ff 41 88 42 ff 41 81 f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}