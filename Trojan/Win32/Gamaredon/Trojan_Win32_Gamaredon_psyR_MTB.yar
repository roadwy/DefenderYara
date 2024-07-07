
rule Trojan_Win32_Gamaredon_psyR_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {15 fc 71 f9 c5 5f 15 08 ce 74 7f 34 95 92 b3 81 1f 8c a7 52 8c 0c af 2f d2 3b db 3f 85 4b 78 26 7a df } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}