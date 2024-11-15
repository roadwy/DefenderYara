
rule Trojan_Win32_Rhadamanthys_CV_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {99 f7 7d d4 8b 45 e0 8b 0c 90 89 4d c8 8b 55 e4 8b 45 ec 8b 0c 90 33 4d c8 8b 55 e4 8b 45 ec 89 0c 90 eb } //5
		$a_01_1 = {88 4d fb 8b 55 e8 8d 04 95 01 00 00 00 99 f7 7d 0c 8b 45 08 8a 0c 10 88 4d fa 8b 55 e8 8d 04 95 02 00 00 00 99 f7 7d 0c } //1
		$a_01_2 = {89 45 f0 8b 55 0c 8b 02 89 45 f4 8b 4d f4 33 4d f0 8b 55 0c 89 0a 8b 45 0c } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}