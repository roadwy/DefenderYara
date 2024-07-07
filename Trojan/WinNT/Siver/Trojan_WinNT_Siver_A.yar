
rule Trojan_WinNT_Siver_A{
	meta:
		description = "Trojan:WinNT/Siver.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 0f 20 c0 a3 90 01 04 25 ff ff fe ff 0f 22 c0 5d 90 00 } //1
		$a_02_1 = {81 7d 1c 03 00 12 00 74 90 01 01 8b 45 f8 e9 90 01 04 83 7d f8 00 0f 8c 90 01 04 c7 45 c8 00 04 00 00 c7 45 cc 00 00 00 00 c7 45 d0 00 02 00 00 c7 45 d4 00 01 00 00 c7 45 d8 01 01 00 00 b9 05 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}