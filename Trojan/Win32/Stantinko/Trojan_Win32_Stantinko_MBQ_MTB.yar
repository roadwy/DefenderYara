
rule Trojan_Win32_Stantinko_MBQ_MTB{
	meta:
		description = "Trojan:Win32/Stantinko.MBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 65 73 74 4c 65 61 6e 49 6e 64 75 6c 67 65 6e 63 65 00 64 6c 63 6c 6f 73 65 5f 32 30 34 39 32 33 61 00 64 6c 65 } //1 敂瑳敌湡湉畤杬湥散搀捬潬敳㉟㐰㈹愳搀敬
	condition:
		((#a_01_0  & 1)*1) >=1
 
}