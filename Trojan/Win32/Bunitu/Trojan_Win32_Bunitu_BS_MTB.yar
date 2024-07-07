
rule Trojan_Win32_Bunitu_BS_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e8 03 a3 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 15 90 01 04 89 15 90 01 04 83 3d 90 01 04 00 0f 85 90 00 } //1
		$a_02_1 = {03 ca 8b 15 90 01 04 03 15 90 01 04 88 0a a1 90 01 04 83 c0 01 a3 90 01 04 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}