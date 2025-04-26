
rule Trojan_Win64_Cobaltstrike_BMA_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.BMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 73 5c 68 79 78 31 39 5c 44 6f 77 6e 6c 6f 61 64 73 5c 61 70 70 73 } //1 Users\hyx19\Downloads\apps
		$a_01_1 = {6d 69 63 72 6f 73 6f 66 74 73 65 72 76 69 63 65 2e 6f 73 73 2d 63 6e 2d 68 61 6e 67 7a 68 6f 75 40 } //1 microsoftservice.oss-cn-hangzhou@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}