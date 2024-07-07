
rule Trojan_Win32_Zenpack_MT_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 37 46 3b f3 90 18 90 18 55 8b ec 51 81 3d 90 02 08 90 18 a1 90 02 08 69 90 02 08 a3 90 02 0d 81 90 02 08 8b 90 02 17 25 90 02 08 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}