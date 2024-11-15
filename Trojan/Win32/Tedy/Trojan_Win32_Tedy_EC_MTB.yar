
rule Trojan_Win32_Tedy_EC_MTB{
	meta:
		description = "Trojan:Win32/Tedy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {2f 74 75 69 67 75 61 6e 67 2f 71 75 64 61 6f } //1 /tuiguang/qudao
		$a_81_1 = {74 61 73 6b 6d 67 72 } //1 taskmgr
		$a_81_2 = {70 72 6f 63 6d 67 72 65 78 } //1 procmgrex
		$a_81_3 = {70 72 6f 63 74 72 65 65 } //1 proctree
		$a_81_4 = {70 6f 73 2e 62 61 69 64 75 2e 63 6f 6d } //1 pos.baidu.com
		$a_81_5 = {35 37 35 34 39 35 } //1 575495
		$a_81_6 = {3c 61 20 69 64 3d 78 20 68 72 65 66 3d 2f 77 7a 73 2f } //1 <a id=x href=/wzs/
		$a_81_7 = {2e 68 74 6d 6c 20 74 61 72 67 65 74 3d 5f 73 65 6c 66 3e 3c 2f 61 3e } //1 .html target=_self></a>
		$a_81_8 = {69 6e 6e 65 72 68 74 6d 6c } //1 innerhtml
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}