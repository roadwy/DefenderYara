
rule Trojan_Win32_Loki_SA_MTB{
	meta:
		description = "Trojan:Win32/Loki.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 03 e8 8d 56 04 8b c3 e8 90 01 04 89 43 01 8b 07 89 43 05 89 1f 83 c3 0d 8b c3 2b c6 3d fc 0f 00 00 7c db 90 00 } //1
		$a_03_1 = {b0 39 8b d3 8b fe 03 fa 8b 15 90 01 04 8a 92 90 01 04 90 02 04 32 d0 88 17 83 05 90 01 04 02 90 02 04 43 81 fb 38 5e 00 00 75 d2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}