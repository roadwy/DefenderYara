
rule Trojan_Win32_VB_AGE{
	meta:
		description = "Trojan:Win32/VB.AGE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 75 bb db fb f7 d8 b9 3e 37 f2 3c 83 d1 00 f7 d9 89 45 90 01 01 89 4d 90 01 01 6a 00 6a 00 6a 00 ff 75 90 01 01 8d 45 90 01 01 50 e8 90 01 02 ff ff 90 00 } //1
		$a_02_1 = {8d 45 08 ff 75 90 01 01 89 45 90 01 01 c7 45 90 01 01 03 40 00 00 8d 5d 90 01 01 e8 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}