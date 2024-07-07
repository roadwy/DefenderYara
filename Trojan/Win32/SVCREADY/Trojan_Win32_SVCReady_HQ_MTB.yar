
rule Trojan_Win32_SVCReady_HQ_MTB{
	meta:
		description = "Trojan:Win32/SVCReady.HQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 54 53 53 38 63 } //1 ETSS8c
		$a_01_1 = {53 35 65 59 39 38 59 6e } //1 S5eY98Yn
		$a_01_2 = {41 39 6f 6b 55 7a 48 42 51 65 7a } //1 A9okUzHBQez
		$a_01_3 = {75 6f 49 71 46 76 6b 57 63 51 } //1 uoIqFvkWcQ
		$a_01_4 = {66 75 6e 63 74 69 6f 6e 20 6d 61 28 61 29 7b 72 65 74 75 72 6e 20 66 75 6e 63 74 69 6f 6e 28 62 29 7b 76 61 72 20 63 3d 62 2e 6e 6f 64 65 4e 61 6d 65 2e 74 6f 4c 6f 77 65 72 43 61 73 65 28 29 3b 72 65 74 75 72 6e } //1 function ma(a){return function(b){var c=b.nodeName.toLowerCase();return
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}