
rule Trojan_Win32_Spyder_LKV_MTB{
	meta:
		description = "Trojan:Win32/Spyder.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {df ff ff 8b 0d 90 01 04 32 04 3e 88 04 0e 46 3b f3 7c 90 00 } //1
		$a_01_1 = {8a 84 0d e0 df ff ff 88 04 0f 83 c1 01 83 d2 00 75 05 83 f9 0e 72 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}