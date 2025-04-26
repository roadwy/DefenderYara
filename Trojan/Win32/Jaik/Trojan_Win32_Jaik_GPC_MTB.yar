
rule Trojan_Win32_Jaik_GPC_MTB{
	meta:
		description = "Trojan:Win32/Jaik.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d7 2b d6 0f af 55 10 03 d3 0f af d3 6b d2 b2 01 95 d0 fc ff ff 8a c3 32 85 cb fc ff ff 66 83 3d 68 31 42 00 00 75 13 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}