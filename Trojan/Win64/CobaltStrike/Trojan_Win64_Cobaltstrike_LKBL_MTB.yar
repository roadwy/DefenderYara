
rule Trojan_Win64_Cobaltstrike_LKBL_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.LKBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 75 61 77 65 69 6f 6f 73 2e 6f 73 73 2d 61 70 2d 73 6f 75 74 68 65 61 73 74 2d 31 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d 2f 73 75 63 63 65 73 73 } //1 huaweioos.oss-ap-southeast-1.aliyuncs.com/success
	condition:
		((#a_01_0  & 1)*1) >=1
 
}