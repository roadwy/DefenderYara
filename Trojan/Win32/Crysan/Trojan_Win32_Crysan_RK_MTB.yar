
rule Trojan_Win32_Crysan_RK_MTB{
	meta:
		description = "Trojan:Win32/Crysan.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0d 98 ee 69 00 56 57 bf 4e e6 40 bb e8 cd 1d e3 ff 3b cf 74 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}