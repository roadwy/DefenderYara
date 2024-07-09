
rule Trojan_Win32_Yangxiay_A{
	meta:
		description = "Trojan:Win32/Yangxiay.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 05 00 00 "
		
	strings :
		$a_02_0 = {5c 52 65 63 79 63 6c 65 72 5c [0-10] 5f 43 6f 6e 66 69 67 2e 49 6e 69 } //1
		$a_00_1 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 2e 74 6d 70 } //1 \Program Files\Internet Explorer\iexplore.exe.tmp
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 67 52 74 45 4f 67 46 52 7a } //1 SYSTEM\CurrentControlSet\Services\gRtEOgFRz
		$a_00_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 41 75 74 67 68 6f 72 68 69 7a 61 74 69 6f 6e } //1 SYSTEM\CurrentControlSet\Services\Autghorhization
		$a_00_4 = {3c 69 66 72 61 6d 65 20 73 72 63 3d 22 00 22 00 20 77 69 64 74 68 3d 22 30 22 00 20 68 65 69 67 68 74 3d 22 30 22 00 20 66 72 61 6d 65 62 6f 72 64 65 72 3d 22 00 30 22 3e 3c 2f 69 66 72 61 6d 65 3e } //10
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*10) >=11
 
}