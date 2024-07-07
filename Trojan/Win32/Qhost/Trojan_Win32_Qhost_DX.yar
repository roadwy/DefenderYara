
rule Trojan_Win32_Qhost_DX{
	meta:
		description = "Trojan:Win32/Qhost.DX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 20 67 6f 6c 6f 73 3d 39 31 2e 31 39 33 2e 31 39 34 2e 31 34 35 } //1 set golos=91.193.194.145
		$a_01_1 = {61 74 74 72 69 62 20 2d 68 20 2d 72 20 25 77 69 6e 64 69 72 25 25 64 72 61 70 6b 61 25 68 6f 73 25 6c 65 77 72 6f 25 } //1 attrib -h -r %windir%%drapka%hos%lewro%
		$a_01_2 = {73 65 74 20 64 72 61 70 6b 61 3d 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c } //1 set drapka=\system32\drivers\etc\
		$a_01_3 = {65 63 68 6f 20 31 32 37 2e 30 2e 30 2e 31 20 6c 6f 63 61 6c 68 6f 73 74 20 3e 3e 20 25 77 69 6e 64 69 72 25 25 64 72 61 70 6b 61 25 68 } //1 echo 127.0.0.1 localhost >> %windir%%drapka%h
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}