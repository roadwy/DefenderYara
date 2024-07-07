
rule Trojan_Win64_Bumblebee_CMN_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.CMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {48 03 ca 48 8d 51 20 e8 90 01 04 84 c0 75 24 ff c3 48 63 cb 48 8b 85 90 01 04 48 8b 95 90 01 04 48 2b c2 48 c1 f8 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}