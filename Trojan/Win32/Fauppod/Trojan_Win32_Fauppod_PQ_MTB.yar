
rule Trojan_Win32_Fauppod_PQ_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 83 ec 04 c7 04 24 90 01 04 83 c4 04 68 90 01 04 83 c4 04 32 02 83 ec 04 c7 04 24 90 01 04 83 c4 04 83 c7 01 88 47 90 01 01 83 c2 01 49 83 ec 04 c7 04 24 90 01 04 83 c4 04 68 90 01 04 83 c4 04 85 c9 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}