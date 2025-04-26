
rule Trojan_Win32_Noexplore_A{
	meta:
		description = "Trojan:Win32/Noexplore.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 64 20 2e 2e 0d 0a 63 64 20 57 69 6e 64 6f 77 73 0d 0a 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 0d 0a 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 0d 0a 64 65 6c 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1
		$a_01_1 = {2e 74 6d 70 00 74 6d 70 66 69 6c 65 00 62 61 74 63 68 66 69 6c 65 2e 62 61 74 00 2e 62 61 74 00 2e 00 00 64 65 6c 20 22 } //1 琮灭琀灭楦敬戀瑡档楦敬戮瑡⸀慢t.搀汥∠
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}