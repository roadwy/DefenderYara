
rule Trojan_Win32_Squida_C{
	meta:
		description = "Trojan:Win32/Squida.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 6c 00 6f 00 6f 00 64 00 69 00 6e 00 67 00 20 00 77 00 69 00 74 00 68 00 20 00 53 00 6c 00 6f 00 77 00 6c 00 6f 00 72 00 69 00 73 00 2e 00 20 00 49 00 50 00 3a 00 } //1 Flooding with Slowloris. IP:
		$a_01_1 = {5c 00 4c 00 6f 00 6e 00 67 00 4c 00 61 00 74 00 2e 00 74 00 78 00 74 00 } //1 \LongLat.txt
		$a_01_2 = {62 00 73 00 5f 00 66 00 75 00 73 00 69 00 6f 00 6e 00 5f 00 62 00 6f 00 74 00 } //1 bs_fusion_bot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}