
rule Trojan_Win32_Tiptuf_A{
	meta:
		description = "Trojan:Win32/Tiptuf.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 65 6e 67 69 6e 65 3d 25 73 26 71 75 65 72 79 3d 25 73 26 69 65 3d 25 73 } //2 &engine=%s&query=%s&ie=%s
		$a_01_1 = {54 43 50 49 50 20 50 61 73 73 2d 74 68 72 6f 75 67 68 20 46 69 6c 74 65 72 } //3 TCPIP Pass-through Filter
		$a_01_2 = {3c 61 20 63 6c 61 73 73 3d 22 79 73 63 68 74 74 6c 20 73 70 74 22 20 68 72 65 66 } //3 <a class="yschttl spt" href
		$a_01_3 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 svchost.exe -k netsvcs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=6
 
}