
rule Trojan_Win32_Poxters_AMTB{
	meta:
		description = "Trojan:Win32/Poxters!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 52 65 73 69 6c 69 65 6e 63 65 20 53 6f 66 74 77 61 72 65 } //Software\Resilience Software  1
		$a_80_1 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2e 63 6f 6d } //*********.com  1
		$a_80_2 = {5c 44 65 73 6b 74 6f 70 5c 50 4f 53 47 72 61 62 62 65 72 5f 6d 75 74 61 74 65 64 2e 65 78 65 } //\Desktop\POSGrabber_mutated.exe  2
		$a_80_3 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 69 6f 72 74 69 5c 69 6f 72 74 69 2e 65 78 65 } //\Application Data\iorti\iorti.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1) >=3
 
}