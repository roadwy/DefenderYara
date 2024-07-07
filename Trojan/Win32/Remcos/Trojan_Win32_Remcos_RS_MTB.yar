
rule Trojan_Win32_Remcos_RS_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c7 dc ac 6d 01 89 39 0f b6 15 90 01 04 89 3d 90 01 04 b9 01 00 00 00 3b d5 76 90 01 01 fe 05 90 01 04 8d 74 2e 2b 83 44 24 10 04 29 4c 24 14 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}