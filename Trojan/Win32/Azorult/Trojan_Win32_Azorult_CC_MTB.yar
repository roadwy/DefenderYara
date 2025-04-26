
rule Trojan_Win32_Azorult_CC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.CC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 33 c0 8d 54 24 24 52 66 89 44 24 20 66 89 4c 24 22 8b 44 24 20 50 51 51 51 ff d6 6a 00 ff d7 } //5
		$a_01_1 = {33 ed 33 db 81 fb 13 4d 00 00 7d 0f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}