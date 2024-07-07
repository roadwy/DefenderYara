
rule Trojan_Win32_Killav_EN{
	meta:
		description = "Trojan:Win32/Killav.EN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 71 71 2e 65 78 65 00 5c 74 65 6e 63 65 6e 74 5c 00 00 00 5c 73 61 66 65 6d 6f 6e 5c 00 00 00 5c 33 36 30 73 61 66 65 } //1
		$a_01_1 = {2f 63 6e 7a 7a 32 2e 68 74 6d 6c 00 } //1 振穮㉺栮浴l
		$a_01_2 = {83 c4 04 68 e8 03 00 00 ff d3 47 83 ff 05 7c c9 68 04 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}