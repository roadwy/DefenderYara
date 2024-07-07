
rule Trojan_Win32_FakeIE_GNH_MTB{
	meta:
		description = "Trojan:Win32/FakeIE.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 63 5c 68 63 61 72 64 } //1 hc\hcard
		$a_01_1 = {6b 69 73 61 66 65 2e 64 6c 6c } //1 kisafe.dll
		$a_01_2 = {73 65 6e 74 69 6e 65 6c 6d 66 63 2e 64 6c 6c } //1 sentinelmfc.dll
		$a_80_3 = {6c 6b 2e 62 72 61 6e 64 2e 73 6f 67 6f 75 2e 63 6f 6d } //lk.brand.sogou.com  1
		$a_80_4 = {73 6f 67 6f 75 2e 63 6f 6d 2f 62 69 6c 6c 5f 63 70 63 } //sogou.com/bill_cpc  1
		$a_80_5 = {6e 6f 6e 6f 64 69 72 68 68 65 63 74 } //nonodirhhect  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}