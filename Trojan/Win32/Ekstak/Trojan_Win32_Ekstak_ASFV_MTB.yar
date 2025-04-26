
rule Trojan_Win32_Ekstak_ASFV_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 ec bc 00 00 00 8d 44 24 00 56 57 50 ff 15 ?? ?? ?? 00 8d 4c 24 18 51 ff 15 ?? ?? ?? 00 8b 54 24 10 } //5
		$a_01_1 = {6a 10 ff d7 66 85 c0 7d 06 81 0e 00 00 00 02 6a 05 e8 ad 01 20 00 6a 11 ff d7 66 85 c0 7d 06 81 0e 00 00 00 04 6a 12 ff d7 66 85 c0 7d 06 81 0e 00 00 00 08 8b c6 5f 5e c3 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}