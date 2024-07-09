
rule Trojan_Win32_Zenpack_MU_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 33 81 ff [0-04] 90 18 46 3b f7 90 18 90 18 55 8b ec 51 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}