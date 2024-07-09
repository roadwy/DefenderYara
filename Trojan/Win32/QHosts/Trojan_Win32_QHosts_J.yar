
rule Trojan_Win32_QHosts_J{
	meta:
		description = "Trojan:Win32/QHosts.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 34 2e 31 39 35 2e 31 35 33 2e 39 34 20 61 70 69 73 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //1 34.195.153.94 apis.google.com
		$a_01_1 = {33 34 2e 31 39 35 2e 31 35 33 2e 39 34 20 77 77 77 2e 67 6f 6f 67 6c 65 61 64 73 65 72 76 69 63 65 73 2e 63 6f 6d } //1 34.195.153.94 www.googleadservices.com
		$a_03_2 = {bb 1d 00 00 73 ?? 8b ?? ?? [0-03] 0f be ?? ?? ?? [0-03] 83 ?? ?? 8b ?? ?? [0-03] 88 ?? ?? ?? [0-03] eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}