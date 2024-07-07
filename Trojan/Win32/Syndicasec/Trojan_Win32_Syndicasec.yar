
rule Trojan_Win32_Syndicasec{
	meta:
		description = "Trojan:Win32/Syndicasec,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 53 79 73 4e 61 74 69 76 65 5c 73 79 73 70 72 65 70 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c } //1 \SysNative\sysprep\cryptbase.dll
		$a_01_1 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 79 73 70 72 65 70 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c } //1 WINDOWS\system32\sysprep\cryptbase.dll
		$a_01_2 = {74 6d 70 69 6e 73 74 2e 6a 73 } //2 tmpinst.js
		$a_01_3 = {50 00 72 00 6f 00 62 00 65 00 53 00 63 00 72 00 69 00 70 00 74 00 46 00 69 00 6e 00 74 00 } //2 ProbeScriptFint
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}