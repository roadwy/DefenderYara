
rule Trojan_Win64_Mikey_AHC_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4f 24 49 03 cb 42 0f b7 14 51 8b 4f 1c 49 03 cb 8b 04 91 48 8d 15 28 ff ff ff 49 8b 0e 49 03 c3 ff d0 } //2
		$a_01_1 = {38 8b 4e 24 49 03 cb 42 0f b7 14 51 8b 4e 1c 49 03 cb 8b 04 91 49 03 c3 48 8d } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}