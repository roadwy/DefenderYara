
rule Trojan_Win64_Stealc_YGB_MTB{
	meta:
		description = "Trojan:Win64/Stealc.YGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 4a 55 46 34 49 38 61 67 67 51 6d 67 75 69 43 39 66 35 64 2f 77 58 47 53 77 37 6d 63 74 58 59 75 4b 54 71 31 47 35 34 52 2f 34 37 49 37 74 4a 71 37 34 48 4d 32 55 4f 41 59 6c 6e 36 62 2f 45 64 37 71 37 38 65 39 6f 36 5a 75 58 4a 30 43 54 6c 6b 48 } //1 SJUF4I8aggQmguiC9f5d/wXGSw7mctXYuKTq1G54R/47I7tJq74HM2UOAYln6b/Ed7q78e9o6ZuXJ0CTlkH
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}