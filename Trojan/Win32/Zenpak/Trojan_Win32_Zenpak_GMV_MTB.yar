
rule Trojan_Win32_Zenpak_GMV_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 20 01 d0 83 ea 06 e8 90 01 04 c3 8d 05 90 01 04 50 c3 8d 05 90 01 04 31 30 48 8d 05 90 01 04 89 38 83 f0 09 89 1d 90 01 04 48 83 ea 02 40 8d 05 90 01 04 01 28 b9 90 00 } //10
		$a_01_1 = {45 61 6c 45 73 6e 65 61 74 61 79 73 78 78 74 } //1 EalEsneataysxxt
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}