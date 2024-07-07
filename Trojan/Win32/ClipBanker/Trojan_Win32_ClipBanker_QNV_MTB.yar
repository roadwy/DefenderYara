
rule Trojan_Win32_ClipBanker_QNV_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.QNV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 73 72 63 5c 53 6f 6c 61 72 69 6f 6e 32 30 31 38 5c 42 69 6e 33 32 5c } //1 C:\src\Solarion2018\Bin32\
		$a_01_1 = {8b 07 83 c4 04 c1 e0 04 89 07 8b 47 04 c1 e0 04 89 47 04 8b 02 c7 47 0c ff 00 00 00 c1 e0 04 5f 89 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}