
rule Trojan_Win32_Cridex_FU_MTB{
	meta:
		description = "Trojan:Win32/Cridex.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b ee 83 c5 90 01 01 4b 0f af dd 05 90 01 04 a3 90 01 04 89 01 a1 90 01 04 2b 05 90 01 04 0f b7 db 89 6c 24 10 89 5c 24 20 89 44 24 18 3d 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}