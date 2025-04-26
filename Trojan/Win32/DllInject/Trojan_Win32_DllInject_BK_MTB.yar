
rule Trojan_Win32_DllInject_BK_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 74 63 79 76 59 76 67 68 62 } //2 RtcyvYvghb
		$a_01_1 = {45 64 74 63 66 4b 68 62 67 76 } //2 EdtcfKhbgv
		$a_01_2 = {49 68 62 67 52 76 67 } //2 IhbgRvg
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}