
rule Trojan_BAT_NjRat_NEBW_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 62 35 35 31 64 33 35 2d 32 61 39 34 2d 34 37 37 35 2d 38 66 63 35 2d 33 37 32 66 38 31 37 63 38 36 39 35 } //5 db551d35-2a94-4775-8fc5-372f817c8695
		$a_01_1 = {4c 69 6e 6b 6f 2e 65 78 65 } //5 Linko.exe
		$a_01_2 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 36 2e 37 2e 30 2e 32 33 39 } //1 Powered by SmartAssembly 6.7.0.239
		$a_01_3 = {48 74 70 4c 20 46 69 6c 65 } //1 HtpL File
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}