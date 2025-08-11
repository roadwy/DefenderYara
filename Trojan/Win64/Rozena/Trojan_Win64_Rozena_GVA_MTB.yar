
rule Trojan_Win64_Rozena_GVA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 31 31 30 2e 34 31 2e 31 37 30 2e 32 33 31 3a 38 30 30 30 2f 62 65 61 63 6f 6e 2e 62 69 6e 2e 65 6e 63 } //2 ://110.41.170.231:8000/beacon.bin.enc
		$a_01_1 = {73 63 68 74 61 73 6b 73 73 68 75 74 64 6f 77 6e } //1 schtasksshutdown
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}