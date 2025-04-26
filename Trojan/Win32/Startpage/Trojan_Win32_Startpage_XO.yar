
rule Trojan_Win32_Startpage_XO{
	meta:
		description = "Trojan:Win32/Startpage.XO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 32 33 34 35 2e 63 6f 6d } //1 .2345.com
		$a_00_1 = {2e 62 61 69 64 75 6f 2e 6f 72 67 2f } //1 .baiduo.org/
		$a_02_2 = {73 5c 6b 62 [0-09] 2e 6c 6f 67 } //1
		$a_00_3 = {73 74 61 74 2e 77 61 6d 6d 65 2e 63 6e 2f 43 38 43 2f 67 6c 2f 63 6e 7a 7a } //1 stat.wamme.cn/C8C/gl/cnzz
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}