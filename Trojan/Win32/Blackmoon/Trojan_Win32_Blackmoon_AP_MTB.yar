
rule Trojan_Win32_Blackmoon_AP_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 79 62 6c 64 61 74 2e 64 6c 6c } //1 dybldat.dll
		$a_01_1 = {77 77 77 2e 35 32 6b 6b 67 2e 63 6f 6d 2f 73 6f 2e 70 68 70 } //1 www.52kkg.com/so.php
		$a_01_2 = {6a 64 2e 6b 78 37 37 38 2e 63 6f 6d 2f 70 6c 75 73 2f 73 65 61 72 63 68 2e 70 68 70 } //1 jd.kx778.com/plus/search.php
		$a_01_3 = {77 77 77 2e 71 69 6b 65 6e 2e 63 6e } //1 www.qiken.cn
		$a_01_4 = {7b 36 41 45 44 42 44 36 44 2d 33 46 42 35 2d 34 31 38 41 2d 38 33 41 36 2d 37 46 34 35 32 32 39 44 43 38 37 32 7d } //1 {6AEDBD6D-3FB5-418A-83A6-7F45229DC872}
		$a_01_5 = {77 77 77 2e 74 61 6f 62 61 6f 2e 63 6f 6d 2f 77 65 62 77 77 2f 77 77 2e 70 68 70 } //1 www.taobao.com/webww/ww.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}