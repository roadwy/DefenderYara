
rule Trojan_Win32_Fauppod_SPVX_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.SPVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_81_0 = {45 74 65 69 61 77 6e 48 71 69 74 65 61 74 69 6c 70 6e 69 69 } //2 EteiawnHqiteatilpnii
		$a_01_1 = {45 74 65 69 61 77 6e 48 71 69 74 65 61 74 69 6c 70 6e 69 69 } //2 EteiawnHqiteatilpnii
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}