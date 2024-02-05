
rule Ransom_Win32_Babuk_ECCP_MTB{
	meta:
		description = "Ransom:Win32/Babuk.ECCP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7d b0 6e 67 20 64 0f 85 d5 04 00 00 81 7d b4 6f 6e 67 20 0f 85 c8 04 00 00 81 7d b8 6c 6f 6f 6b 0f 85 bb 04 00 00 81 7d bc 73 20 6c 69 0f 85 ae 04 00 00 81 7d c0 6b 65 20 68 0f 85 a1 04 00 00 81 7d c4 6f 74 20 64 0f 85 94 04 00 00 81 7d c8 6f 67 21 21 0f 85 87 04 } //00 00 
	condition:
		any of ($a_*)
 
}