
rule Trojan_Win32_Fukru_PF{
	meta:
		description = "Trojan:Win32/Fukru.PF,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be db 83 c3 04 0b d3 eb 1a 80 fb 2b 75 05 83 ca 3e eb 10 80 fb 2f 75 05 83 ca 3f eb 06 c1 fa 02 83 ee 02 85 f6 74 16 83 ee 08 8b da 8b ce d3 fb 47 85 f6 88 5c 07 ff 75 ee 8b 4c 24 18 83 c5 04 49 89 4c 24 18 0f 85 4a fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}