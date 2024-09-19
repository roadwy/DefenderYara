
rule Trojan_AndroidOS_Savestealer_HT{
	meta:
		description = "Trojan:AndroidOS/Savestealer.HT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 48 4d 36 4c 79 39 6c 64 47 56 79 62 6d 6c 30 65 58 42 79 4c 6d 35 6c 64 43 39 68 63 47 6b 76 59 57 4e 6a 62 33 56 75 64 48 4d } //1 aHR0cHM6Ly9ldGVybml0eXByLm5ldC9hcGkvYWNjb3VudHM
		$a_01_1 = {55 48 4d 71 63 52 56 6c 59 53 49 62 59 6e 67 68 58 56 74 4d 5a 32 68 66 46 30 34 4d 58 53 4a 68 53 57 31 36 4b 55 4e 79 64 69 56 56 46 51 42 75 62 42 30 41 53 56 42 42 4a 57 4d 43 4a 47 77 6e 51 41 } //1 UHMqcRVlYSIbYnghXVtMZ2hfF04MXSJhSW16KUNydiVVFQBubB0ASVBBJWMCJGwnQA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}