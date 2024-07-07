
rule Trojan_Win32_Stealergen_VHO_MTB{
	meta:
		description = "Trojan:Win32/Stealergen.VHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 74 65 73 74 2e 62 65 73 74 68 6f 74 65 6c 33 36 30 2e 63 6f 6d 2f 30 30 31 2f 70 75 70 70 65 74 2e 54 78 74 } //2 http://test.besthotel360.com/001/puppet.Txt
		$a_01_1 = {68 6b 65 72 6e 59 32 2e 64 6c 6c } //2 hkernY2.dll
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //2 VirtualProtect
		$a_01_3 = {48 54 54 50 2f 31 2e 31 } //2 HTTP/1.1
		$a_01_4 = {48 54 54 50 2f 31 2e 30 } //2 HTTP/1.0
		$a_01_5 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //2 Accept-Language: zh-cn
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}