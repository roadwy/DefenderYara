
rule Trojan_Win32_Genbhv_D_MSR{
	meta:
		description = "Trojan:Win32/Genbhv.D!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 0f b6 88 90 01 04 0f b6 90 90 90 01 04 2a 88 90 01 04 2a 90 90 90 01 04 88 88 90 01 04 0f b6 88 90 01 04 2a 88 90 01 04 88 90 90 90 01 04 0f b6 90 90 90 01 04 2a 90 90 90 01 04 88 88 90 01 04 88 90 90 90 01 04 83 c0 04 83 f8 10 7c ac c3 90 00 } //1
		$a_02_1 = {40 49 83 f8 10 7c f3 90 09 06 00 00 88 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}