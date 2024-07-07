
rule Trojan_Win32_AutoProxy_GJL_MTB{
	meta:
		description = "Trojan:Win32/AutoProxy.GJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 62 61 69 6a 69 61 68 65 69 2f 73 61 6d 70 6c 65 5f 6d 61 69 6c 73 6c 6f 74 6f 6b } //1 /baijiahei/sample_mailslotok
		$a_01_1 = {31 30 36 2e 35 35 2e 31 34 39 2e 32 34 39 } //1 106.55.149.249
		$a_01_2 = {2f 62 61 69 6a 69 61 68 65 69 2f 64 6c 6c 2e 64 6c 6c } //1 /baijiahei/dll.dll
		$a_01_3 = {2f 62 61 69 6a 69 61 68 65 69 2f 65 78 65 2e 65 78 65 } //1 /baijiahei/exe.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}