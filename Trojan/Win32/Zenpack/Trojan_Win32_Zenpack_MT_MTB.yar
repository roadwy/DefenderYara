
rule Trojan_Win32_Zenpack_MT_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 37 46 3b f3 90 18 90 18 55 8b ec 51 81 3d [0-08] 90 18 a1 [0-08] 69 [0-08] a3 [0-0d] 81 [0-08] 8b [0-17] 25 [0-08] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}